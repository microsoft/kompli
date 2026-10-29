// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <cerrno>
#include <cstddef>
#include <filesystem/FilesystemCollection.hpp>
#include <filesystem/PathInternal.hpp>
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
        stage.mFrames.emplace_back(InPlaceType<const Handle*>{}, static_cast<const Handle*>(nullptr));
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
    faultTransfers = true;
    ComplianceEngine::Filesystem::Path moved(std::move(path));
    using Path = ComplianceEngine::Filesystem::Path;
    using Outcome = ComplianceEngine::Variant<Path, Path::RejectionReason>;
    ComplianceEngine::Result<Outcome> returned(Outcome(ComplianceEngine::InPlaceType<Path>{}, std::move(moved)));
    ComplianceEngine::Result<Outcome> transferred(std::move(returned));
    faultTransfers = false;
    EXPECT_TRUE(transferred.HasValue());
    EXPECT_EQ(0u, transferAllocations);
    EXPECT_TRUE(ComplianceEngine::As<Path>(transferred.Value()).Close().HasValue());
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
