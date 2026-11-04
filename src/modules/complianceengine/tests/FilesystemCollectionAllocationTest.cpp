// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <cerrno>
#include <cstddef>
#include <dirent.h>
#include <filesystem/FilesystemCollection.hpp>
#include <filesystem/PathResolutionStage.hpp>
#include <gtest/gtest.h>
#include <new>
#include <string>
#include <type_traits>
#include <utility>

namespace
{
// The linker wraps operator new only in this dedicated test executable.
// No allocator fault is active during discovery, fixture construction or
// error creation; the real assignment must request the expected bytes.
thread_local bool faultNextCopy = false;
thread_local std::size_t copyBytes = 0;
thread_local std::size_t armedCopies = 0;
thread_local std::size_t allocationAttempts = 0;
thread_local std::size_t failedCopies = 0;
thread_local bool faultTransfers = false;
thread_local std::size_t transferAllocations = 0;
thread_local bool countFreezeAllocations = false;
thread_local std::size_t freezeAllocationAttempts = 0;
thread_local std::size_t failFreezeAt = 0;
} // namespace

namespace ComplianceEngine
{
namespace Filesystem
{
namespace Detail
{
struct ResolvedPathAllocationProbe
{
    static ResolvedPath Staged()
    {
        ResolvedPath stage;
        stage.mFrames.emplace_back(0);
        stage.mAccountedBytes = 160;
        return stage;
    }
};
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

extern "C" void ArmFilesystemCollectionRootCopy(std::size_t bytes) noexcept
{
    if (faultNextCopy)
    {
        faultNextCopy = false;
        copyBytes = bytes;
        ++armedCopies;
    }
}

extern "C" void DisarmFilesystemCollectionRootCopy() noexcept
{
    copyBytes = 0;
}

extern "C" void* __real__Znwm(std::size_t bytes);
extern "C" void* __wrap__Znwm(std::size_t bytes)
{
    if (countFreezeAllocations)
    {
        ++freezeAllocationAttempts;
        if (freezeAllocationAttempts == failFreezeAt)
        {
            countFreezeAllocations = false; // Disarm before unwinding/disposal.
            throw std::bad_alloc();
        }
    }
    if (faultTransfers)
    {
        ++transferAllocations;
        throw std::bad_alloc();
    }
    if (copyBytes != 0)
    {
        ++allocationAttempts;
        if (bytes == copyBytes)
        {
            copyBytes = 0; // Disarm before the resolver constructs its error.
            ++failedCopies;
            throw std::bad_alloc();
        }
    }
    return __real__Znwm(bytes);
}

// The allocation-sensitive close path must not enter GMock: its dispatch can
// allocate before recording the call or reaching the native close action.
// This test-only override observes disposal but delegates the actual syscall
// to the existing native seam; it cannot grant or transfer descriptor ownership.
struct AllocationCloseContext final : MockContext
{
    mutable std::size_t nativeCloses = 0;
    mutable std::size_t failedNativeCloses = 0;

    int CloseFileDescriptor(int fd) const override
    {
        ++nativeCloses;
        const int result = RealCloseFileDescriptor(fd);
        if (result != 0)
            ++failedNativeCloses;
        return result;
    }
};

std::size_t OpenDescriptors()
{
    DIR* stream = ::opendir("/proc/self/fd");
    if (!stream)
        return 0;
    std::size_t count = 0;
    while (::readdir(stream))
        ++count;
    ::closedir(stream);
    return count;
}

TEST(FilesystemCollectionAllocationTest, ResolverResultTransfersDoNotAllocate)
{
    using ComplianceEngine::Filesystem::Detail::ResolvedPath;
    static_assert(std::is_nothrow_move_constructible<ResolvedPath>::value, "Resolver result transfer must be noexcept");
    static_assert(std::is_nothrow_move_assignable<ResolvedPath>::value, "Resolver result replacement must be noexcept");
    auto stage = ComplianceEngine::Filesystem::Detail::ResolvedPathAllocationProbe::Staged();
    // The owning deque has already allocated its map. The Result
    // transfer must move ownership, not construct replacement empty maps.
    faultTransfers = true;
    ComplianceEngine::Result<ResolvedPath> first(std::move(stage));
    ComplianceEngine::Result<ResolvedPath> second(std::move(first));
    faultTransfers = false;
    EXPECT_TRUE(second.HasValue());
    EXPECT_EQ(160u, second.Value().AccountedBytes());
    EXPECT_EQ(0u, transferAllocations);
}

TEST(FilesystemCollectionAllocationTest, PathMoveAndResultTransferDoNotAllocate)
{
    static_assert(std::is_nothrow_move_constructible<ComplianceEngine::Filesystem::Path>::value, "Path move must be noexcept");
    MockContext context;
    ComplianceEngine::Filesystem::ResolverLimits limits;
    limits.shared.retainedBytes = 262144;
    ComplianceEngine::Filesystem::Path::Policy policy;
    policy.mounts = ComplianceEngine::Filesystem::MountPolicy::AllowCrossing;
    auto opened = ComplianceEngine::Filesystem::Path::Make(context, context.GetTempdirPath(), policy, limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    ASSERT_TRUE(opened.Value().Is<ComplianceEngine::Filesystem::Path>());
    auto path = ComplianceEngine::As<ComplianceEngine::Filesystem::Path>(std::move(opened.Value()));
    ASSERT_TRUE(path.FreezeRoot().HasValue());
    faultTransfers = true;
    ComplianceEngine::Filesystem::Path moved(std::move(path));
    using Path = ComplianceEngine::Filesystem::Path;
    using Outcome = ComplianceEngine::Variant<Path, Path::RejectionReason>;
    ComplianceEngine::Result<Outcome> returned(Outcome(ComplianceEngine::InPlaceType<Path>{}, std::move(moved)));
    ComplianceEngine::Result<Outcome> transferred(std::move(returned));
    faultTransfers = false;
    EXPECT_TRUE(transferred.HasValue());
    EXPECT_EQ(0u, transferAllocations);
    EXPECT_TRUE(ComplianceEngine::As<Path>(transferred.Value()).IsFrozen());
}

TEST(FilesystemCollectionAllocationTest, FreezeRootAllocationFailuresPreserveSelectedPinAndNames)
{
    using ComplianceEngine::Filesystem::Path;
    AllocationCloseContext context;
    const std::string directory = context.GetTempdirPath();
    ComplianceEngine::Filesystem::ResolverLimits limits;
    limits.shared.retainedBytes = 262144;
    Path::Policy policy;
    policy.mounts = ComplianceEngine::Filesystem::MountPolicy::AllowCrossing;

    auto control = Path::Make(context, directory, policy, limits);
    ASSERT_TRUE(control.HasValue()) << control.Error().message;
    ASSERT_TRUE(control.Value().Is<Path>());
    Path controlPath = ComplianceEngine::As<Path>(std::move(control.Value()));
    freezeAllocationAttempts = 0;
    failFreezeAt = 0;
    countFreezeAllocations = true;
    auto frozenControl = controlPath.FreezeRoot();
    countFreezeAllocations = false;
    ASSERT_TRUE(frozenControl.HasValue());
    const std::size_t allocations = freezeAllocationAttempts;
    const std::size_t nativeFailuresBefore = context.failedNativeCloses;
    ASSERT_GT(allocations, 2u); // Include deque scratch/entry preparation, not just name copies.

    for (std::size_t failure = 1; failure <= allocations; ++failure)
    {
        SCOPED_TRACE(failure); // Construct trace outside the armed allocation window.
        const std::size_t descriptorsBefore = OpenDescriptors();
        {
            auto opened = Path::Make(context, directory, policy, limits);
            ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
            ASSERT_TRUE(opened.Value().Is<Path>());
            Path path = ComplianceEngine::As<Path>(std::move(opened.Value()));
            freezeAllocationAttempts = 0;
            failFreezeAt = failure;
            countFreezeAllocations = true;
            EXPECT_THROW(path.FreezeRoot(), std::bad_alloc);
            countFreezeAllocations = false;
            EXPECT_EQ(failure, freezeAllocationAttempts);
            EXPECT_FALSE(path.IsFrozen());
            auto frozen = path.FreezeRoot();
            ASSERT_TRUE(frozen.HasValue()) << frozen.Error().message;
            EXPECT_TRUE(path.IsFrozen());
            EXPECT_EQ(directory, path.ToString());
            EXPECT_EQ(directory, path.Root().LookupName());
            EXPECT_EQ(directory, path.Leaf().EffectiveName());
            EXPECT_TRUE(path.Leaf().Stat().HasValue());
        }
        EXPECT_EQ(descriptorsBefore, OpenDescriptors());
        EXPECT_EQ(nativeFailuresBefore, context.failedNativeCloses);
    }
    failFreezeAt = 0;
}

TEST(FilesystemCollectionAllocationTest, RootCopyAllocationFailureReturnsENOMEMBeforeLookup)
{
    // Longer than the small-string buffer, constructed before fault arming.
    const ComplianceEngine::Filesystem::FilesystemCollectionRequest request("/" + std::string(128, 'r'), ComplianceEngine::Filesystem::FilesystemRootKind::File);
    const auto control = ComplianceEngine::Filesystem::ResolveFilesystemCollectionRequest(request);
    ASSERT_TRUE(control.HasValue()) << control.Error().message;
    EXPECT_EQ(request.rootPath, control->rootPath);

    MockContext context;
    EXPECT_CALL(context, LstatPath(testing::_, testing::_)).Times(0);
    EXPECT_CALL(context, OpenNativePath(testing::_, testing::_)).Times(0);

    faultNextCopy = true;
    const auto opened = ComplianceEngine::Filesystem::FTW::Files(request, context);
    EXPECT_FALSE(opened.HasValue());
    if (!opened.HasValue())
    {
        EXPECT_EQ(ENOMEM, opened.Error().code);
    }
    EXPECT_FALSE(faultNextCopy);
    EXPECT_EQ(0u, copyBytes);
    EXPECT_EQ(1u, armedCopies);
    EXPECT_EQ(1u, allocationAttempts);
    EXPECT_EQ(1u, failedCopies);
}

TEST(FilesystemCollectionAllocationTest, ComponentCopyAndMoveAsCopyRetainSourceWithoutAllocation)
{
    AllocationCloseContext context;
    const auto descriptorsBefore = OpenDescriptors();
    std::size_t closesBeforeReplacement = 0;
    {
        ComplianceEngine::Filesystem::ResolverLimits limits;
        limits.shared.retainedBytes = 262144;
        ComplianceEngine::Filesystem::Path::Policy policy;
        policy.mounts = ComplianceEngine::Filesystem::MountPolicy::AllowCrossing;
        auto opened = ComplianceEngine::Filesystem::Path::Make(context, context.GetTempdirPath(), policy, limits);
        ASSERT_TRUE(opened.HasValue());
        ASSERT_TRUE(opened.Value().Is<ComplianceEngine::Filesystem::Path>());
        auto path = ComplianceEngine::As<ComplianceEngine::Filesystem::Path>(std::move(opened.Value()));
        ASSERT_TRUE(path.FreezeRoot().HasValue());
        auto first = path.Leaf();
        auto oldOpened = ComplianceEngine::Filesystem::Path::Make(context, "/proc", policy, limits);
        ASSERT_TRUE(oldOpened.HasValue());
        ASSERT_TRUE(oldOpened.Value().Is<ComplianceEngine::Filesystem::Path>());
        auto oldPath = ComplianceEngine::As<ComplianceEngine::Filesystem::Path>(std::move(oldOpened.Value()));
        ASSERT_TRUE(oldPath.FreezeRoot().HasValue());
        auto replaced = oldPath.Leaf();
        {
            ComplianceEngine::Filesystem::Path retired(std::move(oldPath));
        }
        const auto nativeBefore = OpenDescriptors();
        closesBeforeReplacement = context.nativeCloses;
        const auto nativeFailuresBefore = context.failedNativeCloses;
        EXPECT_CALL(context, OpenNativePath(testing::_, testing::_)).Times(0);
        auto second = first;
        const std::string lookup = first.LookupName();
        const std::string effective = first.EffectiveName();
        const auto inode = first.Acquired().metadata.st_ino;
        struct ResetFaultOnExit
        {
            ~ResetFaultOnExit()
            {
                faultTransfers = false;
            }
        } resetFault;
        faultTransfers = true;
        auto copied = first;
        second = first;
        auto moved(std::move(first));
        second = std::move(first);
        auto& sameComponent = second; // Intentional self-move of the Component wrapper.
        second = std::move(sameComponent);
        replaced = first; // releases the last share of the old acquisition
        faultTransfers = false;
        EXPECT_EQ(closesBeforeReplacement + 1, context.nativeCloses); // Old acquisition final share.
        EXPECT_EQ(nativeFailuresBefore, context.failedNativeCloses);
        EXPECT_EQ(0u, transferAllocations);
        EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&context)); // Native opens remain forbidden.
        EXPECT_EQ(nativeBefore - 1, OpenDescriptors());
        EXPECT_TRUE(copied.Stat().HasValue());
        EXPECT_TRUE(replaced.Stat().HasValue());
        EXPECT_EQ(inode, first.Acquired().metadata.st_ino);
        EXPECT_EQ(inode, moved.Acquired().metadata.st_ino);
        EXPECT_EQ(inode, second.Acquired().metadata.st_ino);
        EXPECT_EQ(lookup, first.LookupName());
        EXPECT_EQ(effective, moved.EffectiveName());
        // The remaining path and shared pin copies dispose only when their final owners leave scope.
    }
    EXPECT_EQ(closesBeforeReplacement + 2, context.nativeCloses); // Remaining acquisition final share.
    EXPECT_EQ(0u, context.failedNativeCloses);
    EXPECT_EQ(descriptorsBefore, OpenDescriptors());
}
