// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// FTW layer: the directory-cursor cases moved out of
// DescriptorBoundaryTest.cpp (Descriptor layer) because they exercise the
// ContextInterface cursor seam (OpenDirectoryCursor/FdOpenDirectory), which
// only exists once the cursor layer is present. Test names are unchanged
// (DescriptorBoundaryTest.*): each test below also covers several
// Descriptor-layer native seams alongside the cursor seam in one assertion,
// so the whole test moved rather than being split (gtest test names must
// be unique per binary, so a single test cannot be split across two files
// under the same name).

#include <DescriptorTestAccess.h>
#include <DirectoryCursorTestAccess.h>
#include <MockContext.h>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem/Descriptor.hpp>
#include <filesystem/ProcfsDescriptorAccess.hpp>
#include <functional>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <sys/statfs.h>
#include <type_traits>
#include <unistd.h>
#include <utility>

namespace
{
using ComplianceEngine::ContextInterface;
using ComplianceEngine::Filesystem::Type;
using ComplianceEngine::Filesystem::Detail::Descriptor;
using ComplianceEngine::Filesystem::Detail::ProcfsDescriptorAccess;
using ComplianceEngine::Tests::DescriptorTestAccess;
using ComplianceEngine::Tests::DirectoryCursorTestAccess;
using Profile = ContextInterface::OpenProfile;
using testing::_;
using testing::NiceMock;

template <typename...>
struct Void
{
    using type = void;
};

// This expression is compiled as part of the ordinary test build. The
// cursor-owner-returning surface must accept both kinds of lvalue and
// neither kind of concrete temporary, including a const temporary (mirrors
// DescriptorBoundaryTest.cpp's OWNER_FACTORY_CONTRACT for its own,
// Descriptor-layer-only seams).
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

OWNER_FACTORY_CONTRACT(Cursor, .OpenDirectoryCursor(std::declval<Descriptor&&>()));
#undef OWNER_FACTORY_CONTRACT

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
    EXPECT_CALL(context, StatNativeDescriptor(_, _)).Times(0);
    EXPECT_CALL(context, StatFilesystemDescriptor(_, _)).Times(0);
    EXPECT_CALL(context, ReadNativeDescriptor(_, _, _)).Times(0);
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
    reject([&] { (void)DescriptorTestAccess::OpenAlias(context, session.Value(), owner, Type::Directory); });
    reject([&] { (void)DescriptorTestAccess::OpenPinAlias(context, session.Value(), owner, Type::Directory); });
    reject([&] { (void)DescriptorTestAccess::Duplicate(context, owner); });
    reject([&] { (void)DescriptorTestAccess::StatFile(context, owner, &metadata); });
    reject([&] { (void)DescriptorTestAccess::StatFilesystem(context, owner, &filesystem); });
    reject([&] { (void)DescriptorTestAccess::ReadFile(context, owner, buffer, sizeof(buffer)); });
    reject([&] { (void)DescriptorTestAccess::ReadLink(context, owner, buffer, sizeof(buffer)); });
    reject([&] { (void)DescriptorTestAccess::StatusFlags(context, owner); });
    reject([&] { (void)DescriptorTestAccess::DescriptorFlags(context, owner); });
    reject([&] { (void)DescriptorTestAccess::ChownPinned(context, owner, ::getuid(), ::getgid()); });
    reject([&] { (void)DescriptorTestAccess::ChmodAlias(context, session.Value(), owner, 0700); });
    reject([&] { (void)DirectoryCursorTestAccess::OpenDirectoryCursor(context, std::move(owner)); });
    reject([&] { (void)DescriptorTestAccess::ReadMountId(session.Value(), owner, 4096); });
    reject([&] { (void)DescriptorTestAccess::CloseOwnedDescriptor(context, owner); });
    EXPECT_TRUE(DescriptorTestAccess::CloseInternally(context, owner));
    EXPECT_EQ(-1, DescriptorTestAccess::ConsumedDescriptor(owner));
    DescriptorTestAccess::Dispose(current);
}

// This replaces the former empty Descriptor/EBADF branch with a consumed
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
    EXPECT_CALL(caller, StatNativeDescriptor(_, _)).Times(0);
    EXPECT_CALL(caller, ReadNativeDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(caller, DuplicateDescriptor(_)).Times(0);
    EXPECT_CALL(caller, FdOpenDirectory(_)).Times(0);
    EXPECT_CALL(caller, CloseNativeDescriptor(_)).Times(0);
    struct stat metadata = {};
    EXPECT_EQ(EINVAL, DescriptorTestAccess::Duplicate(caller, owner).Error().code);
    EXPECT_EQ(EINVAL, DescriptorTestAccess::OpenAt(caller, owner, "child", Profile::PinChild).Error().code);
    EXPECT_EQ(EINVAL, DirectoryCursorTestAccess::OpenDirectoryCursor(caller, std::move(owner)).Error().code);
    errno = 0;
    EXPECT_EQ(-1, DescriptorTestAccess::StatFile(caller, owner, &metadata));
    EXPECT_EQ(EINVAL, errno);
    errno = 0;
    EXPECT_EQ(-1, DescriptorTestAccess::ReadFile(caller, owner, nullptr, 0));
    EXPECT_EQ(EINVAL, errno);
    errno = 0;
    const auto rejectedClose = DescriptorTestAccess::CloseOwnedDescriptor(caller, owner);
    ASSERT_FALSE(rejectedClose.HasValue());
    EXPECT_EQ(EINVAL, rejectedClose.Error().code);
    EXPECT_EQ(fd, DescriptorTestAccess::ConsumedDescriptor(owner));
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&caller));
    EXPECT_TRUE(DescriptorTestAccess::CloseOwnedDescriptor(foreign, owner));
    EXPECT_EQ(-1, DescriptorTestAccess::ConsumedDescriptor(owner));
}

TEST(DescriptorBoundaryTest, FailedDirectoryTransferKeepsOwnerAndPrimaryError)
{
    NiceMock<MockContext> context;
    const auto before = OpenDescriptors();
    auto pinned = DescriptorTestAccess::OpenAbsolutePin(context, context.GetTempdirPath().c_str());
    auto procfs = DescriptorTestAccess::ProcfsAccess(context);
    ASSERT_TRUE(pinned.HasValue());
    ASSERT_TRUE(procfs.HasValue());
    auto active = DescriptorTestAccess::OpenAlias(context, procfs.Value(), pinned.Value(), Type::Directory);
    ASSERT_TRUE(active.HasValue()) << active.Error().message;
    auto duplicate = DescriptorTestAccess::Duplicate(context, active.Value());
    ASSERT_TRUE(duplicate.HasValue());
    DescriptorTestAccess::Dispose(active.Value());
    procfs = ComplianceEngine::Error("Release procfs roles", EINVAL);
    DescriptorTestAccess::Dispose(pinned.Value());
    Descriptor owner = std::move(duplicate).Value();
    const int fd = DescriptorTestAccess::ConsumedDescriptor(owner);
    EXPECT_CALL(context, FdOpenDirectory(fd)).Times(1).WillOnce([](int) -> DIR* {
        errno = ENOTDIR;
        return nullptr;
    });
    auto failed = DirectoryCursorTestAccess::OpenDirectoryCursor(context, std::move(owner));
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(ENOTDIR, failed.Error().code);
    EXPECT_EQ(fd, DescriptorTestAccess::ConsumedDescriptor(owner));
    EXPECT_CALL(context, CloseNativeDescriptor(fd)).Times(1).WillOnce([&](int value) { return context.RealCloseNativeDescriptor(value); });
    DescriptorTestAccess::Dispose(owner);
    EXPECT_EQ(before, OpenDescriptors());
}
} // namespace
