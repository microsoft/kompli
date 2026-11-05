// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <DescriptorTestAccess.h>
#include <MockContext.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem/Descriptor.hpp>
#include <filesystem/Handle.hpp>
#include <filesystem/ProcfsDescriptorAccess.hpp>
#include <fstream>
#include <functional>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iterator>
#include <linux/magic.h>
#include <map>
#include <stdexcept>
#include <string>
#include <sys/statfs.h>
#include <sys/wait.h>
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

// Track acquisition epochs, not native integers: retired bootstrap slots are reused.
struct ProcfsEpochs
{
    std::array<int, 16> descriptors{};
    std::array<unsigned, 16> closes{};
    std::array<struct stat, 16> metadata{};
    std::array<struct statfs, 16> filesystems{};
    std::size_t acquired = 0;
    bool invalid = false;

    void Acquired(int fd) noexcept
    {
        if (fd < 0)
            return;
        if (acquired == descriptors.size())
        {
            invalid = true;
            return;
        }
        descriptors[acquired] = fd;
        if (::fstat(fd, &metadata[acquired]) != 0 || ::fstatfs(fd, &filesystems[acquired]) != 0)
            invalid = true;
        ++acquired;
    }
    bool LiveRole(int fd, std::size_t role) const noexcept
    {
        return role < acquired && !closes[role] && descriptors[role] == fd;
    }
    void Closed(int fd) noexcept
    {
        for (std::size_t i = acquired; i > 0; --i)
            if (LiveRole(fd, i - 1))
            {
                ++closes[i - 1];
                return;
            }
        invalid = true;
    }
    bool AllClosed() const noexcept
    {
        if (invalid)
            return false;
        for (std::size_t i = 0; i < acquired; ++i)
            if (closes[i] != 1)
                return false;
        return true;
    }
};

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

std::size_t OpenDescriptors()
{
    DIR* directory = ::opendir("/proc/self/fd");
    if (nullptr == directory)
        return 0;
    std::size_t total = 0;
    while (nullptr != ::readdir(directory))
        ++total;
    ::closedir(directory);
    return total;
}

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

TEST(DescriptorBoundaryTest, MovedDescriptorLogsFailedCloseOnlyOnce)
{
    struct LoggingContext : NiceMock<MockContext>
    {
        OsConfigLogHandle GetLogHandle() const noexcept override
        {
            ++logAttempts;
            return MockContext::GetLogHandle();
        }
        mutable int logAttempts = 0;
    } context;
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, "/proc");
    ASSERT_TRUE(opened.HasValue());
    Descriptor original = std::move(opened).Value();
    Descriptor moved(std::move(original));
    EXPECT_FALSE(DescriptorTestAccess::ConsumedDescriptor(original) != -1);
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int fd) {
        EXPECT_EQ(0, ::close(fd));
        errno = EIO;
        return -1;
    });
    EXPECT_NO_THROW(moved.Close());
    EXPECT_EQ(1, context.logAttempts);
    moved.Close();
    EXPECT_FALSE(DescriptorTestAccess::ConsumedDescriptor(moved) != -1);
}

TEST(DescriptorBoundaryTest, NativeCloseErrorRelinquishesDescriptorBeforeReuse)
{
    NiceMock<MockContext> context;
    const std::string logPath = context.GetTempdirPath() + "/error-release.log";
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
        errno = EIO;
        return -1;
    });
    EXPECT_NO_THROW(owner.Close());
    EXPECT_FALSE(DescriptorTestAccess::ConsumedDescriptor(owner) != -1);
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
    EXPECT_FALSE(DescriptorTestAccess::ConsumedDescriptor(owner) != -1);
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
    EXPECT_FALSE(DescriptorTestAccess::ConsumedDescriptor(owners.front()) != -1);
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

TEST(DescriptorBoundaryTest, ConsumedOwnersThrowBeforeEveryNativeAccess)
{
    NiceMock<MockContext> context;
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, "/proc");
    ASSERT_TRUE(opened.HasValue());
    Descriptor owner = std::move(opened).Value();
    Descriptor current(std::move(owner));
    ASSERT_EQ(-1, DescriptorTestAccess::ConsumedDescriptor(owner));
    auto session = DescriptorTestAccess::ProcfsAccess(context);
    ASSERT_TRUE(session.HasValue()) << session.Error().message;
    auto reject = [&](const std::function<void()>& operation) {
        try
        {
            operation();
            FAIL() << "consumed descriptor unexpectedly accessed";
        }
        catch (const std::logic_error& error)
        {
            EXPECT_NE(std::string::npos, std::string(error.what()).find("use after move"));
        }
    };
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(context, DuplicateDescriptor(_)).Times(0);
    EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(0);
    EXPECT_CALL(context, StatFilesystemDescriptor(_, _)).Times(0);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(context, StatusFlagsDescriptor(_)).Times(0);
    EXPECT_CALL(context, DescriptorFlagsDescriptor(_)).Times(0);
    EXPECT_CALL(context, ChownPinnedFileDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(context, ChmodPinnedAlias(_, _, _)).Times(0);
    EXPECT_CALL(context, FdOpenDirectory(_)).Times(0);
    struct stat metadata = {};
    struct statfs filesystem = {};
    char buffer[32] = {};
    reject([&] { (void)DescriptorTestAccess::OpenAt(context, owner, "child", Profile::PinChild); });
    reject([&] { (void)DescriptorTestAccess::OpenFdinfo(context, session.Value(), owner); });
    reject([&] { (void)DescriptorTestAccess::OpenAlias(context, session.Value(), owner, true); });
    reject([&] { (void)DescriptorTestAccess::OpenPinAlias(context, session.Value(), owner, true); });
    reject([&] { (void)DescriptorTestAccess::Duplicate(context, owner); });
    reject([&] { (void)DescriptorTestAccess::StatFile(context, owner, &metadata); });
    reject([&] { (void)DescriptorTestAccess::StatFilesystem(context, owner, &filesystem); });
    reject([&] { (void)DescriptorTestAccess::ReadFile(context, owner, buffer, sizeof(buffer)); });
    reject([&] { (void)DescriptorTestAccess::ReadLink(context, owner, buffer, sizeof(buffer)); });
    reject([&] { (void)DescriptorTestAccess::StatusFlags(context, owner); });
    reject([&] { (void)DescriptorTestAccess::DescriptorFlags(context, owner); });
    reject([&] { (void)DescriptorTestAccess::ChownPinned(context, owner, ::getuid(), ::getgid()); });
    reject([&] { (void)DescriptorTestAccess::ChmodAlias(context, session.Value(), owner, 0700); });
    reject([&] { (void)DescriptorTestAccess::OpenDirectoryCursor(context, std::move(owner)); });
    reject([&] { (void)session.Value().ReadMountId(owner, 4096); });
    reject([&] { (void)DescriptorTestAccess::CloseOwnedDescriptor(context, owner); });
    EXPECT_EQ(0, DescriptorTestAccess::CloseInternally(context, owner));
    EXPECT_EQ(-1, DescriptorTestAccess::ConsumedDescriptor(owner));
    current.Close();
}

TEST(DescriptorBoundaryTest, MovedSessionRolesRemainOwnedUntilLastOwnerDies)
{
    NiceMock<MockContext> context;
    context.SetManagedDescriptorAllowanceForTesting(3); // three bootstrap pins peak, two retained roles
    const auto before = OpenDescriptors();
    {
        auto opened = DescriptorTestAccess::ProcfsAccess(context);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        ProcfsDescriptorAccess session = std::move(opened).Value();
        ProcfsDescriptorAccess moved(std::move(session));
        for (std::size_t index = 0; index < 2; ++index)
        {
            EXPECT_EQ(-1, DescriptorTestAccess::ConsumedProcfsRole(session, index));
            EXPECT_GE(DescriptorTestAccess::ConsumedProcfsRole(moved, index), 0);
        }
        auto target = DescriptorTestAccess::OpenAbsolutePin(context, "/");
        ASSERT_TRUE(target.HasValue()); // one free slot after bootstrap retirement
        EXPECT_EQ(EMFILE, DescriptorTestAccess::OpenAbsolutePin(context, "/").Error().code);
        target.Value().Close();
    }
    EXPECT_EQ(before, OpenDescriptors());
    EXPECT_TRUE(DescriptorTestAccess::OpenAbsolutePin(context, "/").HasValue());
}

TEST(DescriptorBoundaryTest, PartialProcfsFactoryRollsBackEveryAcquiredRole)
{
    for (std::size_t failure = 0; failure < 7; ++failure)
    {
        SCOPED_TRACE(failure);
        NiceMock<MockContext> context;
        const auto before = OpenDescriptors();
        std::size_t attempts = 0;
        ProcfsEpochs epochs;
        ON_CALL(context, OpenNativePath(_, _)).WillByDefault([&](const char* path, int flags) {
            if (attempts++ == failure)
            {
                errno = ENOENT;
                return -1;
            }
            const int fd = context.RealOpenNativePath(path, flags);
            epochs.Acquired(fd);
            return fd;
        });
        ON_CALL(context, OpenNativeAt(_, _, _)).WillByDefault([&](int directory, const char* name, int flags) {
            if (attempts++ == failure)
            {
                errno = ENOENT;
                return -1;
            }
            const int fd = context.RealOpenNativeAt(directory, name, flags);
            epochs.Acquired(fd);
            return fd;
        });
        EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
            epochs.Closed(fd);
            return context.RealCloseFileDescriptor(fd);
        });
        auto opened = DescriptorTestAccess::ProcfsAccess(context);
        ASSERT_FALSE(opened.HasValue());
        EXPECT_EQ(ENOENT, opened.Error().code);
        EXPECT_EQ(failure + 1, attempts);
        EXPECT_EQ(failure, epochs.acquired);
        EXPECT_TRUE(epochs.AllClosed());
        EXPECT_EQ(before, OpenDescriptors());
    }
}

TEST(DescriptorBoundaryTest, ProcfsSessionPinsNamedVerifiedRolesAndReleasesEachOnce)
{
    NiceMock<MockContext> context;
    context.SetManagedDescriptorAllowanceForTesting(3);
    const auto before = OpenDescriptors();
    const std::string pid = std::to_string(context.RealNativeProcessId());
    const std::string tid = std::to_string(context.RealNativeThreadId());
    const std::array<const char*, 7> expected{{"/proc", "self", pid.c_str(), "task", tid.c_str(), "fd", "fdinfo"}};
    ProcfsEpochs epochs;
    bool namesMatch = true;
    auto observe = [&](int fd, const char* name) {
        if (fd < 0)
            return;
        namesMatch = namesMatch && epochs.acquired < expected.size() && std::strcmp(expected[epochs.acquired], name) == 0;
        epochs.Acquired(fd);
    };
    ON_CALL(context, OpenNativePath(_, _)).WillByDefault([&](const char* path, int flags) {
        const int fd = context.RealOpenNativePath(path, flags);
        observe(fd, path);
        return fd;
    });
    ON_CALL(context, OpenNativeAt(_, _, _)).WillByDefault([&](int parent, const char* name, int flags) {
        const int fd = context.RealOpenNativeAt(parent, name, flags);
        observe(fd, name);
        return fd;
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
        epochs.Closed(fd);
        return context.RealCloseFileDescriptor(fd);
    });
    {
        auto opened = DescriptorTestAccess::ProcfsAccess(context);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        ASSERT_EQ(7u, epochs.acquired);
        EXPECT_TRUE(namesMatch);
        for (std::size_t i = 0; i < epochs.acquired; ++i)
        {
            EXPECT_TRUE(S_ISDIR(epochs.metadata[i].st_mode)) << i;
            EXPECT_EQ(PROC_SUPER_MAGIC, epochs.filesystems[i].f_type) << i;
        }
        EXPECT_EQ(epochs.metadata[1].st_ino, epochs.metadata[2].st_ino); // self and numeric PID
        EXPECT_EQ(epochs.metadata[1].st_dev, epochs.metadata[2].st_dev);
        EXPECT_EQ(2u, OpenDescriptors() - before);
        auto spare = DescriptorTestAccess::OpenAbsolutePin(context, "/");
        ASSERT_TRUE(spare.HasValue());
        EXPECT_EQ(EMFILE, DescriptorTestAccess::OpenAbsolutePin(context, "/").Error().code);
        spare.Value().Close();
        EXPECT_TRUE(epochs.closes[0] == 1 && epochs.closes[1] == 1 && epochs.closes[2] == 1 && epochs.closes[3] == 1 && epochs.closes[4] == 1);
        for (std::size_t i = 0; i < 2; ++i)
        {
            const int fd = DescriptorTestAccess::ConsumedProcfsRole(opened.Value(), i);
            EXPECT_GE(fd, 0);
            EXPECT_TRUE(epochs.LiveRole(fd, i + 5));
        }
    }
    EXPECT_EQ(before, OpenDescriptors());
    EXPECT_TRUE(epochs.AllClosed());
}

TEST(DescriptorBoundaryTest, ProcfsSuccessfulSessionDisposalDoesNotRetryFailedClose)
{
    NiceMock<MockContext> context;
    const auto before = OpenDescriptors();
    ProcfsEpochs epochs;
    bool oneFailure = false;
    ON_CALL(context, OpenNativePath(_, _)).WillByDefault([&](const char* path, int flags) {
        const int fd = context.RealOpenNativePath(path, flags);
        epochs.Acquired(fd);
        return fd;
    });
    ON_CALL(context, OpenNativeAt(_, _, _)).WillByDefault([&](int parent, const char* name, int flags) {
        const int fd = context.RealOpenNativeAt(parent, name, flags);
        epochs.Acquired(fd);
        return fd;
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
        epochs.Closed(fd);
        const int status = context.RealCloseFileDescriptor(fd);
        if (status != 0)
            epochs.invalid = true;
        if (!oneFailure)
        {
            oneFailure = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    {
        auto opened = DescriptorTestAccess::ProcfsAccess(context);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        EXPECT_EQ(7u, epochs.acquired);
        for (std::size_t i = 0; i < 5; ++i)
            EXPECT_EQ(1u, epochs.closes[i]);
        for (std::size_t i = 0; i < 2; ++i)
            EXPECT_TRUE(epochs.LiveRole(DescriptorTestAccess::ConsumedProcfsRole(opened.Value(), i), i + 5));
    }
    EXPECT_TRUE(oneFailure);
    EXPECT_TRUE(epochs.AllClosed());
    EXPECT_EQ(before, OpenDescriptors());
}

TEST(DescriptorBoundaryTest, ProcfsFactoryExhaustionRollsBackEachRole)
{
    // Bootstrap needs three simultaneous owners; all seven acquisitions reuse slots.
    for (std::size_t capacity = 0; capacity < 3; ++capacity)
    {
        SCOPED_TRACE(capacity);
        NiceMock<MockContext> context;
        context.SetManagedDescriptorAllowanceForTesting(capacity);
        const auto before = OpenDescriptors();
        ProcfsEpochs epochs;
        ON_CALL(context, OpenNativePath(_, _)).WillByDefault([&](const char* path, int flags) {
            const int fd = context.RealOpenNativePath(path, flags);
            epochs.Acquired(fd);
            return fd;
        });
        ON_CALL(context, OpenNativeAt(_, _, _)).WillByDefault([&](int parent, const char* name, int flags) {
            const int fd = context.RealOpenNativeAt(parent, name, flags);
            epochs.Acquired(fd);
            return fd;
        });
        EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
            epochs.Closed(fd);
            return context.RealCloseFileDescriptor(fd);
        });
        auto attempt = DescriptorTestAccess::ProcfsAccess(context);
        ASSERT_FALSE(attempt.HasValue());
        EXPECT_EQ(EMFILE, attempt.Error().code);
        EXPECT_EQ(capacity, epochs.acquired);
        EXPECT_TRUE(epochs.AllClosed());
        EXPECT_EQ(before, OpenDescriptors());
        context.SetManagedDescriptorAllowanceForTesting(3);
        auto retry = DescriptorTestAccess::ProcfsAccess(context);
        ASSERT_TRUE(retry.HasValue()) << retry.Error().message;
    }
}

TEST(DescriptorBoundaryTest, ProcfsRoleVerificationAndFinalBindingFailuresRollbackOwners)
{
    // self is verified after pid opens; fd is verified after fdinfo opens.
    const std::array<std::size_t, 7> verificationEpoch{{1, 3, 3, 4, 5, 7, 7}};
    for (std::size_t role = 0; role < 7; ++role)
    {
        SCOPED_TRACE(role);
        NiceMock<MockContext> context;
        const auto before = OpenDescriptors();
        ProcfsEpochs epochs;
        ON_CALL(context, OpenNativePath(_, _)).WillByDefault([&](const char* path, int flags) {
            int fd = context.RealOpenNativePath(path, flags);
            epochs.Acquired(fd);
            return fd;
        });
        ON_CALL(context, OpenNativeAt(_, _, _)).WillByDefault([&](int parent, const char* name, int flags) {
            int fd = context.RealOpenNativeAt(parent, name, flags);
            epochs.Acquired(fd);
            return fd;
        });
        ON_CALL(context, StatFilesystemDescriptor(_, _)).WillByDefault([&](int fd, struct statfs* out) {
            if (epochs.LiveRole(fd, role))
            {
                errno = EIO;
                return -1;
            }
            return ::fstatfs(fd, out);
        });
        EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
            epochs.Closed(fd);
            return context.RealCloseFileDescriptor(fd);
        });
        auto failed = DescriptorTestAccess::ProcfsAccess(context);
        ASSERT_FALSE(failed.HasValue());
        EXPECT_EQ(EPROTO, failed.Error().code);
        EXPECT_EQ(verificationEpoch[role], epochs.acquired);
        EXPECT_TRUE(epochs.AllClosed());
        EXPECT_EQ(before, OpenDescriptors());
    }
    for (int changed : {1, 2})
    {
        SCOPED_TRACE(changed);
        NiceMock<MockContext> context;
        const auto before = OpenDescriptors();
        int calls = 0;
        if (changed == 1)
            ON_CALL(context, NativeProcessId()).WillByDefault([&] { return context.RealNativeProcessId() + (calls++ > 0 ? 1 : 0); });
        else
            ON_CALL(context, NativeThreadId()).WillByDefault([&] { return context.RealNativeThreadId() + (calls++ > 0 ? 1 : 0); });
        ProcfsEpochs epochs;
        ON_CALL(context, OpenNativePath(_, _)).WillByDefault([&](const char* path, int flags) {
            const int fd = context.RealOpenNativePath(path, flags);
            epochs.Acquired(fd);
            return fd;
        });
        ON_CALL(context, OpenNativeAt(_, _, _)).WillByDefault([&](int parent, const char* name, int flags) {
            const int fd = context.RealOpenNativeAt(parent, name, flags);
            epochs.Acquired(fd);
            return fd;
        });
        EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
            epochs.Closed(fd);
            return context.RealCloseFileDescriptor(fd);
        });
        auto failed = DescriptorTestAccess::ProcfsAccess(context);
        ASSERT_FALSE(failed.HasValue());
        EXPECT_EQ(EPROTO, failed.Error().code);
        EXPECT_EQ(2, calls);
        EXPECT_EQ(7u, epochs.acquired);
        EXPECT_TRUE(epochs.AllClosed());
        EXPECT_EQ(before, OpenDescriptors());
    }
}

TEST(DescriptorBoundaryTest, ProcfsRejectsNonDirectoryOrWrongFilesystemForEveryRole)
{
    const std::array<std::size_t, 7> verificationEpoch{{1, 3, 3, 4, 5, 7, 7}};
    for (bool wrongFilesystem : {false, true})
        for (std::size_t role = 0; role < 7; ++role)
        {
            SCOPED_TRACE(wrongFilesystem);
            SCOPED_TRACE(role);
            NiceMock<MockContext> context;
            const auto before = OpenDescriptors();
            ProcfsEpochs epochs;
            ON_CALL(context, OpenNativePath(_, _)).WillByDefault([&](const char* name, int flags) {
                const int fd = context.RealOpenNativePath(name, flags);
                epochs.Acquired(fd);
                return fd;
            });
            ON_CALL(context, OpenNativeAt(_, _, _)).WillByDefault([&](int parent, const char* name, int flags) {
                const int fd = context.RealOpenNativeAt(parent, name, flags);
                epochs.Acquired(fd);
                return fd;
            });
            ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
                const int status = context.RealStatFileDescriptor(fd, metadata);
                if (!wrongFilesystem && epochs.LiveRole(fd, role) && status == 0)
                    metadata->st_mode = S_IFREG | 0400;
                return status;
            });
            ON_CALL(context, StatFilesystemDescriptor(_, _)).WillByDefault([&](int fd, struct statfs* filesystem) {
                const int status = ::fstatfs(fd, filesystem);
                if (wrongFilesystem && epochs.LiveRole(fd, role) && status == 0)
                    filesystem->f_type = 0;
                return status;
            });
            EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
                epochs.Closed(fd);
                return context.RealCloseFileDescriptor(fd);
            });
            auto opened = DescriptorTestAccess::ProcfsAccess(context);
            ASSERT_FALSE(opened.HasValue());
            EXPECT_EQ(EPROTO, opened.Error().code);
            EXPECT_EQ(verificationEpoch[role], epochs.acquired);
            EXPECT_TRUE(epochs.AllClosed());
            EXPECT_EQ(before, OpenDescriptors());
        }
}

TEST(DescriptorBoundaryTest, ProcfsSelfPidMismatchAndFinalIdentityStatRollback)
{
    for (bool finalStat : {false, true})
    {
        SCOPED_TRACE(finalStat);
        NiceMock<MockContext> context;
        const auto before = OpenDescriptors();
        ProcfsEpochs epochs;
        int observations = 0;
        const char* chosen = finalStat ? "fdinfo" : "self";
        std::size_t selectedEpoch = 16;
        ON_CALL(context, OpenNativePath(_, _)).WillByDefault([&](const char* path, int flags) {
            const int fd = context.RealOpenNativePath(path, flags);
            epochs.Acquired(fd);
            return fd;
        });
        ON_CALL(context, OpenNativeAt(_, _, _)).WillByDefault([&](int parent, const char* name, int flags) {
            const int fd = context.RealOpenNativeAt(parent, name, flags);
            if (fd >= 0 && std::strcmp(chosen, name) == 0)
                selectedEpoch = epochs.acquired;
            epochs.Acquired(fd);
            return fd;
        });
        ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
            const int result = context.RealStatFileDescriptor(fd, metadata);
            if (epochs.LiveRole(fd, selectedEpoch) && result == 0 && ++observations == 2)
            {
                if (finalStat)
                {
                    errno = EIO;
                    return -1;
                }
                ++metadata->st_ino; // self and numeric PID were distinct acquisitions
            }
            return result;
        });
        EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
            epochs.Closed(fd);
            return context.RealCloseFileDescriptor(fd);
        });
        auto opened = DescriptorTestAccess::ProcfsAccess(context);
        ASSERT_FALSE(opened.HasValue());
        EXPECT_EQ(finalStat ? EIO : EPROTO, opened.Error().code);
        EXPECT_EQ(2, observations);
        EXPECT_EQ(finalStat ? 7u : 3u, epochs.acquired);
        EXPECT_TRUE(epochs.AllClosed());
        EXPECT_EQ(before, OpenDescriptors());
    }
}

TEST(DescriptorBoundaryTest, ProcfsFailureClosesEveryAcquiredRoleOnceEvenWhenCloseReportsFailure)
{
    NiceMock<MockContext> context;
    const auto before = OpenDescriptors();
    ProcfsEpochs epochs;
    ON_CALL(context, OpenNativePath(_, _)).WillByDefault([&](const char* path, int flags) {
        const int fd = context.RealOpenNativePath(path, flags);
        epochs.Acquired(fd);
        return fd;
    });
    ON_CALL(context, OpenNativeAt(_, _, _)).WillByDefault([&](int parent, const char* name, int flags) {
        if (std::strcmp(name, "fdinfo") == 0)
        {
            errno = ENOENT;
            return -1;
        }
        const int fd = context.RealOpenNativeAt(parent, name, flags);
        epochs.Acquired(fd);
        return fd;
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
        epochs.Closed(fd);
        const int status = context.RealCloseFileDescriptor(fd);
        if (status != 0)
            epochs.invalid = true;
        errno = EIO;
        return -1;
    });
    auto failed = DescriptorTestAccess::ProcfsAccess(context);
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(ENOENT, failed.Error().code);
    EXPECT_EQ(6u, epochs.acquired);
    EXPECT_TRUE(epochs.AllClosed());
    EXPECT_EQ(before, OpenDescriptors());
}

TEST(DescriptorBoundaryTest, MoveAssignmentReleasesOldOwnerExactlyOnce)
{
    NiceMock<MockContext> context;
    auto first = DescriptorTestAccess::OpenAbsolutePin(context, "/proc");
    auto second = DescriptorTestAccess::OpenAbsolutePin(context, "/");
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    Descriptor old = std::move(first).Value();
    Descriptor incoming = std::move(second).Value();
    const int oldFd = DescriptorTestAccess::ConsumedDescriptor(old);
    const int incomingFd = DescriptorTestAccess::ConsumedDescriptor(incoming);
    EXPECT_CALL(context, CloseFileDescriptor(oldFd)).Times(1).WillOnce([&](int fd) { return context.RealCloseFileDescriptor(fd); });
    old = std::move(incoming);
    EXPECT_EQ(-1, DescriptorTestAccess::ConsumedDescriptor(incoming));
    EXPECT_EQ(incomingFd, DescriptorTestAccess::ConsumedDescriptor(old));
    auto& sameOwner = old;
    old = std::move(sameOwner);
    EXPECT_EQ(incomingFd, DescriptorTestAccess::ConsumedDescriptor(old));
    EXPECT_CALL(context, CloseFileDescriptor(incomingFd)).Times(1).WillOnce([&](int fd) { return context.RealCloseFileDescriptor(fd); });
    old.Close();
}

TEST(DescriptorBoundaryTest, NativeDescriptorZeroIsOwnedNotAnEmptySentinel)
{
    NiceMock<MockContext> context;
    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if (0 == child)
    {
        ::close(STDIN_FILENO);
        auto opened = DescriptorTestAccess::OpenAbsolutePin(context, "/proc");
        if (!opened.HasValue())
            ::_exit(2);
        Descriptor owner = std::move(opened).Value();
        if (0 != DescriptorTestAccess::ConsumedDescriptor(owner))
            ::_exit(3);
        struct stat metadata = {};
        if (0 != DescriptorTestAccess::StatFile(context, owner, &metadata))
            ::_exit(4);
        owner.Close();
        ::_exit(0);
    }
    int status = 0;
    ASSERT_EQ(child, ::waitpid(child, &status, 0));
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(0, WEXITSTATUS(status));
}

TEST(DescriptorBoundaryTest, ExplicitSentinelCloseReportsButDestructionRemainsSilent)
{
    struct DiagnosticContext : NiceMock<MockContext>
    {
        OsConfigLogHandle GetLogHandle() const noexcept override
        {
            ++attempts;
            return MockContext::GetLogHandle();
        }
        mutable int attempts = 0;
    } context;
    {
        auto opened = DescriptorTestAccess::OpenAbsolutePin(context, "/proc");
        ASSERT_TRUE(opened.HasValue());
        Descriptor first = std::move(opened).Value();
        Descriptor owner(std::move(first));
        ASSERT_EQ(-1, DescriptorTestAccess::ConsumedDescriptor(first));
        EXPECT_CALL(context, CloseFileDescriptor(_)).Times(0);
        EXPECT_NO_THROW(first.Close());
        EXPECT_EQ(1, context.attempts);
        EXPECT_NO_THROW(first.Close());
        EXPECT_EQ(2, context.attempts); // each *explicit* misuse reports once
        testing::Mock::VerifyAndClearExpectations(&context);
        owner.Close();
    }
    EXPECT_EQ(2, context.attempts); // consumed destructor never reports
}

TEST(DescriptorBoundaryTest, MovedFromProcfsSessionThrowsBeforeProfileAndAliasWork)
{
    NiceMock<MockContext> context;
    auto pin = DescriptorTestAccess::OpenAbsolutePin(context, "/");
    ASSERT_TRUE(pin.HasValue());
    auto acquired = DescriptorTestAccess::ProcfsAccess(context);
    ASSERT_TRUE(acquired.HasValue());
    ProcfsDescriptorAccess session = std::move(acquired).Value();
    ProcfsDescriptorAccess moved(std::move(session));
    for (std::size_t index = 0; index < 2; ++index)
    {
        EXPECT_EQ(-1, DescriptorTestAccess::ConsumedProcfsRole(session, index));
        EXPECT_GE(DescriptorTestAccess::ConsumedProcfsRole(moved, index), 0);
    }
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(0);
    EXPECT_CALL(context, ChmodPinnedAlias(_, _, _)).Times(0);
    EXPECT_THROW((void)DescriptorTestAccess::OpenFdinfo(context, session, pin.Value()), std::logic_error);
    EXPECT_THROW((void)DescriptorTestAccess::OpenAlias(context, session, pin.Value(), true), std::logic_error);
    EXPECT_THROW((void)DescriptorTestAccess::OpenPinAlias(context, session, pin.Value(), true), std::logic_error);
    EXPECT_THROW((void)DescriptorTestAccess::ChmodAlias(context, session, pin.Value(), 0700), std::logic_error);
    EXPECT_THROW((void)session.ReadMountId(pin.Value(), 4096), std::logic_error);
    testing::Mock::VerifyAndClearExpectations(&context);
    auto live = moved.ReadMountId(pin.Value(), 4096);
    ASSERT_TRUE(live.HasValue()) << live.Error().message;
    EXPECT_GT(live.Value(), 0u);
}

TEST(DescriptorBoundaryTest, CombinedInvalidOwnerInputsThrowBeforeProfilesCapsAndProcfs)
{
    NiceMock<MockContext> context;
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, "/proc");
    ASSERT_TRUE(opened.HasValue());
    Descriptor consumed = std::move(opened).Value();
    Descriptor live(std::move(consumed));
    auto access = DescriptorTestAccess::ProcfsAccess(context);
    ASSERT_TRUE(access.HasValue());
    ProcfsDescriptorAccess moved(std::move(access.Value()));
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(context, OpenNativePath(_, _)).Times(0);
    EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(0);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(context, NativeProcessId()).Times(0);
    EXPECT_CALL(context, NativeThreadId()).Times(0);
    EXPECT_THROW((void)DescriptorTestAccess::OpenAt(context, consumed, "child", static_cast<Profile>(255)), std::logic_error);
    EXPECT_THROW((void)DescriptorTestAccess::OpenFdinfo(context, access.Value(), consumed), std::logic_error);
    EXPECT_THROW((void)DescriptorTestAccess::OpenAlias(context, access.Value(), consumed, false), std::logic_error);
    EXPECT_THROW((void)DescriptorTestAccess::OpenPinAlias(context, access.Value(), consumed, false), std::logic_error);
    EXPECT_THROW((void)DescriptorTestAccess::ChmodAlias(context, access.Value(), consumed, 0700), std::logic_error);
    EXPECT_THROW((void)access.Value().ReadMountId(consumed, 0), std::logic_error);
    EXPECT_THROW((void)moved.ReadMountId(consumed, 0), std::logic_error);
    EXPECT_THROW((void)access.Value().ReadMountId(live, 0), std::logic_error);
    auto invalidCap = moved.ReadMountId(live, 0);
    ASSERT_FALSE(invalidCap.HasValue());
    EXPECT_EQ(EINVAL, invalidCap.Error().code);
    testing::Mock::VerifyAndClearExpectations(&context);
}

TEST(DescriptorBoundaryTest, ProcfsRoleBindsTaskAndRejectsCrossContextTargets)
{
    NiceMock<MockContext> context;
    NiceMock<MockContext> foreign;
    auto pin = DescriptorTestAccess::OpenAbsolutePin(context, "/");
    auto other = DescriptorTestAccess::OpenAbsolutePin(foreign, "/");
    auto session = DescriptorTestAccess::ProcfsAccess(context);
    ASSERT_TRUE(pin.HasValue());
    ASSERT_TRUE(other.HasValue());
    ASSERT_TRUE(session.HasValue());
    EXPECT_EQ(EINVAL, session.Value().ReadMountId(other.Value(), 4096).Error().code);
    EXPECT_EQ(EINVAL, DescriptorTestAccess::OpenFdinfo(context, session.Value(), other.Value()).Error().code);
    ON_CALL(context, NativeThreadId()).WillByDefault([&] { return context.RealNativeThreadId() + 1; });
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(context, ChmodPinnedAlias(_, _, _)).Times(0);
    EXPECT_EQ(EINVAL, DescriptorTestAccess::OpenAlias(context, session.Value(), pin.Value(), true).Error().code);
    EXPECT_EQ(EINVAL, DescriptorTestAccess::OpenPinAlias(context, session.Value(), pin.Value(), true).Error().code);
    EXPECT_EQ(EINVAL, DescriptorTestAccess::OpenFdinfo(context, session.Value(), pin.Value()).Error().code);
    EXPECT_EQ(EINVAL, session.Value().ReadMountId(pin.Value(), 4096).Error().code);
    errno = 0;
    EXPECT_EQ(-1, DescriptorTestAccess::ChmodAlias(context, session.Value(), pin.Value(), 0700));
    EXPECT_EQ(EINVAL, errno);
    testing::Mock::VerifyAndClearExpectations(&context);
}

// ADR-0044 replaces the former empty Descriptor/EBADF branch with a consumed
// owner; the foreign-context rejection remains an independent authority check.
TEST(DescriptorBoundaryTest, ForeignOwnerRejectsEveryNativeBoundaryWithoutConsumingIt)
{
    NiceMock<MockContext> caller;
    NiceMock<MockContext> foreign;
    auto opened = DescriptorTestAccess::OpenAbsolutePin(foreign, "/proc");
    ASSERT_TRUE(opened.HasValue());
    Descriptor owner = std::move(opened).Value();
    const int fd = DescriptorTestAccess::ConsumedDescriptor(owner);
    EXPECT_CALL(caller, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(caller, StatFileDescriptor(_, _)).Times(0);
    EXPECT_CALL(caller, ReadFileDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(caller, DuplicateDescriptor(_)).Times(0);
    EXPECT_CALL(caller, FdOpenDirectory(_)).Times(0);
    EXPECT_CALL(caller, CloseFileDescriptor(_)).Times(0);
    struct stat metadata = {};
    EXPECT_EQ(EINVAL, DescriptorTestAccess::Duplicate(caller, owner).Error().code);
    EXPECT_EQ(EINVAL, DescriptorTestAccess::OpenAt(caller, owner, "child", Profile::PinChild).Error().code);
    EXPECT_EQ(EINVAL, DescriptorTestAccess::OpenDirectoryCursor(caller, std::move(owner)).Error().code);
    errno = 0;
    EXPECT_EQ(-1, DescriptorTestAccess::StatFile(caller, owner, &metadata));
    EXPECT_EQ(EINVAL, errno);
    errno = 0;
    EXPECT_EQ(-1, DescriptorTestAccess::ReadFile(caller, owner, nullptr, 0));
    EXPECT_EQ(EINVAL, errno);
    errno = 0;
    EXPECT_EQ(-1, DescriptorTestAccess::CloseOwnedDescriptor(caller, owner));
    EXPECT_EQ(EINVAL, errno);
    EXPECT_EQ(fd, DescriptorTestAccess::ConsumedDescriptor(owner));
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&caller));
    EXPECT_EQ(0, DescriptorTestAccess::CloseOwnedDescriptor(foreign, owner));
    EXPECT_EQ(-1, DescriptorTestAccess::ConsumedDescriptor(owner));
}

TEST(DescriptorBoundaryTest, ProcfsRoleReleaseReportsTwoDistinctFailuresAndStillClosesAllSeven)
{
    NiceMock<MockContext> context;
    const std::string logPath = context.GetTempdirPath() + "/role-release-errors.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    const auto before = OpenDescriptors();
    ProcfsEpochs epochs;
    unsigned failedReports = 0;
    ON_CALL(context, OpenNativePath(_, _)).WillByDefault([&](const char* path, int flags) {
        const int fd = context.RealOpenNativePath(path, flags);
        epochs.Acquired(fd);
        return fd;
    });
    ON_CALL(context, OpenNativeAt(_, _, _)).WillByDefault([&](int parent, const char* name, int flags) {
        const int fd = context.RealOpenNativeAt(parent, name, flags);
        epochs.Acquired(fd);
        return fd;
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(7).WillRepeatedly([&](int fd) {
        epochs.Closed(fd);
        const int status = context.RealCloseFileDescriptor(fd);
        if (status != 0)
            epochs.invalid = true;
        if (failedReports < 2)
        {
            errno = failedReports++ == 0 ? EACCES : EIO;
            return -1;
        }
        return status;
    });
    {
        auto opened = DescriptorTestAccess::ProcfsAccess(context);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        EXPECT_EQ(7u, epochs.acquired);
        for (std::size_t i = 0; i < 2; ++i)
            EXPECT_TRUE(epochs.LiveRole(DescriptorTestAccess::ConsumedProcfsRole(opened.Value(), i), i + 5));
    }
    EXPECT_EQ(before, OpenDescriptors());
    EXPECT_TRUE(epochs.AllClosed());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    std::ifstream record(logPath);
    ASSERT_TRUE(record.is_open());
    const std::string text((std::istreambuf_iterator<char>(record)), std::istreambuf_iterator<char>());
    for (int code : {EACCES, EIO})
    {
        const std::string entry = "Cannot close internal filesystem descriptor: " + std::to_string(code);
        const auto first = text.find(entry);
        ASSERT_NE(std::string::npos, first);
        EXPECT_EQ(std::string::npos, text.find(entry, first + entry.size()));
    }
}

TEST(DescriptorBoundaryTest, FailedDirectoryTransferKeepsOwnerAndPrimaryError)
{
    NiceMock<MockContext> context;
    const auto before = OpenDescriptors();
    auto pinned = DescriptorTestAccess::OpenAbsolutePin(context, context.GetTempdirPath().c_str());
    auto procfs = DescriptorTestAccess::ProcfsAccess(context);
    ASSERT_TRUE(pinned.HasValue());
    ASSERT_TRUE(procfs.HasValue());
    auto active = DescriptorTestAccess::OpenAlias(context, procfs.Value(), pinned.Value(), true);
    ASSERT_TRUE(active.HasValue()) << active.Error().message;
    auto duplicate = DescriptorTestAccess::Duplicate(context, active.Value());
    ASSERT_TRUE(duplicate.HasValue());
    active.Value().Close();
    procfs = ComplianceEngine::Error("Release procfs roles", EINVAL);
    pinned.Value().Close();
    Descriptor owner = std::move(duplicate).Value();
    const int fd = DescriptorTestAccess::ConsumedDescriptor(owner);
    EXPECT_CALL(context, FdOpenDirectory(fd)).Times(1).WillOnce([](int) -> DIR* {
        errno = ENOTDIR;
        return nullptr;
    });
    auto failed = DescriptorTestAccess::OpenDirectoryCursor(context, std::move(owner));
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(ENOTDIR, failed.Error().code);
    EXPECT_EQ(fd, DescriptorTestAccess::ConsumedDescriptor(owner));
    EXPECT_CALL(context, CloseFileDescriptor(fd)).Times(1).WillOnce([&](int value) { return context.RealCloseFileDescriptor(value); });
    owner.Close();
    EXPECT_EQ(before, OpenDescriptors());
}

TEST(DescriptorBoundaryTest, ExplicitConsumedCloseLogsUseAfterMoveButInternalCleanupIsSilent)
{
    NiceMock<MockContext> context;
    const std::string logPath = context.GetTempdirPath() + "/explicit-consumed-close.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, "/proc");
    ASSERT_TRUE(opened.HasValue());
    Descriptor source = std::move(opened).Value();
    {
        Descriptor live(std::move(source));
        EXPECT_CALL(context, CloseFileDescriptor(_)).Times(0);
        source.Close();
        source.Close();
        EXPECT_EQ(0, DescriptorTestAccess::CloseInternally(context, source)); // Silent, unlike explicit Close.
        ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        live.Close();
    }
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    std::ifstream record(logPath);
    ASSERT_TRUE(record.is_open());
    const std::string text((std::istreambuf_iterator<char>(record)), std::istreambuf_iterator<char>());
    const std::string entry = "Descriptor: use after move (no ownership) on explicit Close";
    const auto first = text.find(entry);
    ASSERT_NE(std::string::npos, first);
    const auto second = text.find(entry, first + entry.size());
    ASSERT_NE(std::string::npos, second);
    EXPECT_EQ(std::string::npos, text.find(entry, second + entry.size()));
}

} // namespace
