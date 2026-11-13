// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <dirent.h>
#include <filesystem/FilesystemCollection.hpp>
#include <filesystem/Path.hpp>
#include <fstream>
#include <gtest/gtest.h>
#include <new>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <utility>

namespace
{
// The global operator new/delete below are replaced only in this dedicated
// test executable. No allocator fault is active during discovery, fixture
// construction or error creation; the real assignment must request the
// expected bytes.
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
// Keep these five sites in sync with the isolated FilesystemCollection TU.
enum class TestCheckpoint : unsigned
{
    FrameReserve = 1,
    InversePreparation,
    AfterApply,
    BeforeOffer,
    InverseRestore,
};
thread_local unsigned armedCheckpoint = 0;
thread_local std::size_t checkpointHits = 0;
thread_local unsigned armedHandleAllocationSite = 0;
thread_local bool faultHandleAllocation = false;
thread_local std::size_t handleAllocationFaults = 0;
thread_local bool faultInverseAllocation = false;
thread_local std::size_t inverseAllocationFailures = 0;
struct ResetCheckpointOnExit
{
    ~ResetCheckpointOnExit() noexcept
    {
        armedCheckpoint = 0;
    }
};
} // namespace

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

extern "C" bool TripFilesystemCollectionCheckpoint(unsigned site) noexcept
{
    if (site != armedCheckpoint)
        return false;
    armedCheckpoint = 0; // Disarm before unwinding or disposing native resources.
    ++checkpointHits;
    return true;
}

extern "C" bool ArmFilesystemCollectionHandleAllocation(unsigned site) noexcept
{
    if (armedHandleAllocationSite != site)
        return false;
    armedHandleAllocationSite = 0;
    faultHandleAllocation = true;
    return true;
}
extern "C" void DisarmFilesystemCollectionHandleAllocation() noexcept
{
    faultHandleAllocation = false;
}

extern "C" void ArmFilesystemCollectionInverseAllocation() noexcept
{
    faultInverseAllocation = true;
}

extern "C" void DisarmFilesystemCollectionInverseAllocation() noexcept
{
    faultInverseAllocation = false;
}

namespace
{
// `-Wl,--wrap=_Znwm` only rewrites undefined references resolved among this
// executable's own linked objects. At -O2/-O3 (unsanitized GCC Release),
// `_GLIBCXX_ASSERTIONS` is off (only auto-enabled when `__OPTIMIZE__` is
// undefined), so libstdc++'s `_GLIBCXX_EXTERN_TEMPLATE` stays positive and
// `std::string`'s copy path (the root-copy allocation under test) resolves
// to the explicit instantiation already built into libstdc++.so; that
// internal `operator new` call is never rewritten, so the injected fault
// never fires. Replacing the global allocation functions is honored
// everywhere, including inside libstdc++.so, because the main executable's
// definitions take priority over a shared library's in the dynamic symbol
// scope. Forwarding to `std::malloc`/`std::free` keeps this ASan-compatible
// in the sanitized Debug trees: ASan intercepts `malloc`/`free` themselves
// (ahead of libc, by load order), so heap tracking still applies even
// though this replacement also takes priority over ASan's own `operator new`.
void* AllocateBytes(std::size_t bytes)
{
    if (bytes == 0)
        bytes = 1;
    for (;;)
    {
        if (void* ptr = std::malloc(bytes))
            return ptr;
        std::new_handler handler = std::get_new_handler();
        if (!handler)
            throw std::bad_alloc();
        handler();
    }
}
} // namespace

void* operator new(std::size_t bytes)
{
    if (faultHandleAllocation)
    {
        faultHandleAllocation = false;
        ++handleAllocationFaults;
        throw std::bad_alloc();
    }
    if (faultInverseAllocation)
    {
        faultInverseAllocation = false; // Never fault disposal, logging or native seams.
        ++inverseAllocationFailures;
        throw std::bad_alloc();
    }
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
    return AllocateBytes(bytes);
}

void operator delete(void* ptr) noexcept
{
    std::free(ptr);
}

void operator delete(void* ptr, std::size_t) noexcept
{
    std::free(ptr);
}

// Not subject to fault injection: no test here arms an array-new path, and
// `__wrap__Znwm` never covered `_Znam` either.
void* operator new[](std::size_t bytes)
{
    return AllocateBytes(bytes);
}

void operator delete[](void* ptr) noexcept
{
    std::free(ptr);
}

// The allocation-sensitive close path must not enter GMock: its dispatch can
// allocate before recording the call or reaching the native close action.
// This test-only override observes disposal but delegates the actual syscall
// to the existing native seam; it cannot grant or transfer descriptor ownership.
struct AllocationCloseContext final : ::testing::StrictMock<MockContext>
{
    mutable std::size_t nativeCloses = 0;
    mutable std::size_t failedNativeCloses = 0;
    mutable std::size_t actualNativeCloseFailures = 0;
    mutable bool reportNativeCloseFailure = false;
    mutable ino_t trackedInode = 0;
    mutable std::size_t trackedCloses = 0;

    ComplianceEngine::Result<void> CloseFileDescriptor(int fd) const noexcept override
    {
        ++nativeCloses;
        struct stat closing = {};
        if (trackedInode != 0 && ::fstat(fd, &closing) == 0 && closing.st_ino == trackedInode)
            ++trackedCloses;
        auto result = RealCloseFileDescriptor(fd);
        if (!result)
            ++actualNativeCloseFailures;
        if (!result || reportNativeCloseFailure)
        {
            ++failedNativeCloses;
            if (reportNativeCloseFailure)
                return ComplianceEngine::Error(EIO); // Native close has already released the fd.
        }
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

// Native mocks and fixture setup are never subject to allocation interception.
struct PreparedTraversalFixture
{
    AllocationCloseContext context;
    std::string root = context.GetTempdirPath() + "/ftw-fault";
    std::string directory = root + "/branch";
    std::string file = directory + "/file";
    ComplianceEngine::Filesystem::FilesystemCollectionRequest request{root, ComplianceEngine::Filesystem::FilesystemRootKind::Directory};

    PreparedTraversalFixture()
    {
        request.direction = ComplianceEngine::Filesystem::FilesystemDirection::Down;
        if (::mkdir(root.c_str(), 0700) != 0 || ::mkdir(directory.c_str(), 0700) != 0)
            throw std::runtime_error("Failed to prepare FTW fault fixture");
        std::ofstream output(file);
        output << "content";
        if (!output)
            throw std::runtime_error("Failed to prepare FTW fault file");
        // No test using this fixture sets its own EXPECT_CALL; each counts
        // close/open-descriptor behavior by hand (nativeCloses,
        // actualNativeCloseFailures), not gMock cardinality.
        context.AllowIncidentalNativeAccess();
    }
};

// Metadata is a plain value member of Handle, not a separate heap
// allocation; the allocation under fault is the one remaining heap
// allocation between acquiring a pin and publishing it: make_shared's
// combined control-block-plus-Handle block for the root and the unpublished
// child Component. Both sites still release the unpublished pin's
// descriptor exactly once and leave the prior Path state untouched.
TEST(FilesystemCollectionAllocationTest, StagedRootAndChildHandleAllocationReleaseOnlyUnpublishedPin)
{
    using ComplianceEngine::Filesystem::Path;
    AllocationCloseContext context;
    // No EXPECT_CALL in this test constrains any native seam; the close
    // count under test (context.trackedCloses) is tracked by the
    // AllocationCloseContext override itself, not gMock cardinality.
    context.AllowIncidentalNativeAccess();
    ComplianceEngine::Filesystem::ResolverLimits limits;
    limits.shared.retainedBytes = 262144;
    Path::Policy policy;
    policy.mounts = ComplianceEngine::Filesystem::MountPolicy::CrossMounts;
    const auto baseline = OpenDescriptors();
    struct stat root = {};
    ASSERT_EQ(0, ::stat("/", &root));
    context.trackedInode = root.st_ino;
    armedHandleAllocationSite = 1;
    const auto rootFaults = handleAllocationFaults;
    EXPECT_THROW(Path::Make(context, "/", policy, limits), std::bad_alloc);
    EXPECT_EQ(0u, armedHandleAllocationSite);
    EXPECT_FALSE(faultHandleAllocation);
    EXPECT_EQ(rootFaults + 1, handleAllocationFaults);
    EXPECT_EQ(1u, context.trackedCloses);
    EXPECT_EQ(baseline, OpenDescriptors());

    const std::string file = context.MakeTempfile("unpublished child");
    struct stat child = {};
    ASSERT_EQ(0, ::stat(file.c_str(), &child));
    auto acquired = Path::Make(context, context.GetTempdirPath(), policy, limits);
    ASSERT_TRUE(acquired.HasValue());
    ASSERT_TRUE(acquired.Value().Is<Path>());
    Path path = ComplianceEngine::As<Path>(std::move(acquired).Value());
    const std::string previous = path.ToString();
    const auto pins = path.RetainedDescriptors();
    context.trackedInode = child.st_ino;
    context.trackedCloses = 0;
    armedHandleAllocationSite = 2;
    const auto childFaults = handleAllocationFaults;
    const auto beforeResolve = OpenDescriptors();
    EXPECT_THROW(path.Resolve(file.substr(file.find_last_of("/") + 1), policy), std::bad_alloc);
    EXPECT_EQ(0u, armedHandleAllocationSite);
    EXPECT_FALSE(faultHandleAllocation);
    EXPECT_EQ(childFaults + 1, handleAllocationFaults);
    EXPECT_EQ(1u, context.trackedCloses);
    EXPECT_EQ(beforeResolve, OpenDescriptors());
    EXPECT_EQ(previous, path.ToString());
    EXPECT_EQ(pins, path.RetainedDescriptors());
    auto retry = path.Resolve(file.substr(file.find_last_of("/") + 1), policy);
    ASSERT_TRUE(retry.HasValue());
    ASSERT_TRUE(retry.Value().Is<Path::Step>());
    EXPECT_EQ(child.st_ino, ComplianceEngine::As<Path::Step>(retry.Value()).Metadata().Stat().st_ino);
}

TEST(FilesystemCollectionAllocationTest, StepResultAndVariantTransfersDoNotAllocate)
{
    using ComplianceEngine::Filesystem::Path;
    static_assert(std::is_nothrow_move_constructible<Path::Step>::value, "Step move cannot allocate");
    static_assert(std::is_nothrow_move_assignable<Path::Step>::value, "Step replacement cannot allocate");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    Path::Policy policy;
    policy.mounts = ComplianceEngine::Filesystem::MountPolicy::CrossMounts;
    ComplianceEngine::Filesystem::ResolverLimits limits;
    limits.shared.retainedBytes = 262144;
    auto opened = Path::Make(context, context.GetTempdirPath(), policy, limits);
    ASSERT_TRUE(opened.HasValue());
    ASSERT_TRUE(opened.Value().Is<Path>());
    Path path = ComplianceEngine::As<Path>(std::move(opened.Value()));
    // The acquired child is independent of the source path.
    const std::string child = context.MakeTempfile("test");
    auto resolved = path.Resolve(child.substr(child.find_last_of('/') + 1), policy);
    ASSERT_TRUE(resolved.HasValue());
    ASSERT_TRUE(resolved.Value().Is<Path::Step>());
    Path::Step step = ComplianceEngine::As<Path::Step>(std::move(resolved.Value()));
    using Outcome = ComplianceEngine::Variant<Path::Step, Path::RejectionReason>;
    struct ResetFaultOnExit
    {
        ~ResetFaultOnExit()
        {
            faultTransfers = false;
        }
    } reset;
    faultTransfers = true;
    Path::Step moved(std::move(step));
    ComplianceEngine::Result<Outcome> first(Outcome(ComplianceEngine::InPlaceType<Path::Step>{}, std::move(moved)));
    ComplianceEngine::Result<Outcome> second(std::move(first));
    faultTransfers = false;
    EXPECT_TRUE(second.HasValue());
    EXPECT_TRUE(second.Value().Is<Path::Step>());
    EXPECT_TRUE(step.Target().Stat().HasValue());
    EXPECT_EQ(0u, transferAllocations);
}

TEST(FilesystemCollectionAllocationTest, PathMoveAndResultTransferDoNotAllocate)
{
    static_assert(std::is_nothrow_move_constructible<ComplianceEngine::Filesystem::Path>::value, "Path move must be noexcept");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    ComplianceEngine::Filesystem::ResolverLimits limits;
    limits.shared.retainedBytes = 262144;
    ComplianceEngine::Filesystem::Path::Policy policy;
    policy.mounts = ComplianceEngine::Filesystem::MountPolicy::CrossMounts;
    auto opened = ComplianceEngine::Filesystem::Path::Make(context, context.GetTempdirPath(), policy, limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    ASSERT_TRUE(opened.Value().Is<ComplianceEngine::Filesystem::Path>());
    auto path = ComplianceEngine::As<ComplianceEngine::Filesystem::Path>(std::move(opened.Value()));
    ASSERT_TRUE(path.Freeze().HasValue());
    faultTransfers = true;
    ComplianceEngine::Filesystem::Path moved(std::move(path));
    using Path = ComplianceEngine::Filesystem::Path;
    using Outcome = ComplianceEngine::Variant<Path, Path::RejectionReason>;
    ComplianceEngine::Result<Outcome> returned(Outcome(ComplianceEngine::InPlaceType<Path>{}, std::move(moved)));
    ComplianceEngine::Result<Outcome> transferred(std::move(returned));
    faultTransfers = false;
    EXPECT_TRUE(transferred.HasValue());
    EXPECT_EQ(0u, transferAllocations);
    EXPECT_GE(ComplianceEngine::As<Path>(transferred.Value()).Size(), 1u);
    EXPECT_EQ(path.Size(), ComplianceEngine::As<Path>(transferred.Value()).Size());
}

TEST(FilesystemCollectionAllocationTest, FreezeRootAllocationFailuresPreserveSelectedPinAndNames)
{
    using ComplianceEngine::Filesystem::Path;
    AllocationCloseContext context;
    // No EXPECT_CALL in this test constrains any native seam; close-failure
    // counts under test (context.failedNativeCloses) are tracked by the
    // AllocationCloseContext override itself, not gMock cardinality.
    context.AllowIncidentalNativeAccess();
    const std::string directory = context.GetTempdirPath();
    ComplianceEngine::Filesystem::ResolverLimits limits;
    limits.shared.retainedBytes = 262144;
    Path::Policy policy;
    policy.mounts = ComplianceEngine::Filesystem::MountPolicy::CrossMounts;

    auto control = Path::Make(context, directory, policy, limits);
    ASSERT_TRUE(control.HasValue()) << control.Error().message;
    ASSERT_TRUE(control.Value().Is<Path>());
    Path controlPath = ComplianceEngine::As<Path>(std::move(control.Value()));
    freezeAllocationAttempts = 0;
    failFreezeAt = 0;
    countFreezeAllocations = true;
    auto frozenControl = controlPath.Freeze();
    countFreezeAllocations = false;
    ASSERT_TRUE(frozenControl.HasValue());
    const std::size_t allocations = freezeAllocationAttempts;
    const std::size_t nativeFailuresBefore = context.failedNativeCloses;
    ASSERT_GT(allocations, 0u); // Capture every preparation allocation before publication.

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
            EXPECT_THROW(path.Freeze(), std::bad_alloc);
            countFreezeAllocations = false;
            EXPECT_EQ(failure, freezeAllocationAttempts);
            EXPECT_EQ(directory, path.ToString());
            EXPECT_EQ("/", path.Root().Metadata().LookupName());
            auto frozen = path.Freeze();
            ASSERT_TRUE(frozen.HasValue()) << frozen.Error().message;
            EXPECT_TRUE(frozen.Value());
            EXPECT_FALSE(path.Freeze().Value());
            EXPECT_EQ(directory, path.ToString());
            EXPECT_EQ("/", path.Root().Metadata().LookupName());
            EXPECT_EQ(directory, path.Leaf().Metadata().EffectiveName());
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

    ::testing::StrictMock<MockContext> context;
    // The test wants ZERO calls on these seams; production code returns
    // ENOMEM before any other native seam is reached (baseline measurement
    // confirms no incidental warnings here), so no additional catch-all is
    // declared.
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
    // OpenNativePath stays in the catch-all even though this test later adds
    // its own Times(0) on it: the catch-all is declared here, strictly
    // before that narrower expectation, so the newer Times(0) still wins for
    // every call made during/after the copy-move section (see MockContext.h
    // helper comment).
    context.AllowIncidentalNativeAccess();
    const auto before = OpenDescriptors();
    const auto closesBefore = context.nativeCloses;
    {
        ComplianceEngine::Filesystem::ResolverLimits limits;
        limits.shared.retainedBytes = 262144;
        ComplianceEngine::Filesystem::Path::Policy policy;
        policy.mounts = ComplianceEngine::Filesystem::MountPolicy::CrossMounts;
        auto opened = ComplianceEngine::Filesystem::Path::Make(context, context.GetTempdirPath(), policy, limits);
        ASSERT_TRUE(opened.HasValue());
        ASSERT_TRUE(opened.Value().Is<ComplianceEngine::Filesystem::Path>());
        auto path = ComplianceEngine::As<ComplianceEngine::Filesystem::Path>(std::move(opened.Value()));
        auto first = path.Leaf();
        auto second = first;
        const auto identity = first.Metadata().Stat().st_ino;
        const auto lookup = first.Metadata().LookupName();
        EXPECT_CALL(context, OpenNativePath(testing::_, testing::_)).Times(0);
        struct ResetFaultOnExit
        {
            ~ResetFaultOnExit()
            {
                faultTransfers = false;
            }
        } reset;
        faultTransfers = true;
        auto copied = first;
        second = first;
        auto moved(std::move(first));
        second = std::move(first);
        auto& self = second;
        second = std::move(self);
        faultTransfers = false;
        EXPECT_EQ(0u, transferAllocations);
        EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        // VerifyAndClearExpectations() above cleared every EXPECT_CALL on
        // context, including the fixture-wide catch-all; the Stat() calls
        // below are incidental again and need it re-declared.
        context.AllowIncidentalNativeAccess();
        EXPECT_EQ(identity, first.Metadata().Stat().st_ino);
        EXPECT_EQ(identity, second.Metadata().Stat().st_ino);
        EXPECT_EQ(identity, moved.Metadata().Stat().st_ino);
        EXPECT_TRUE(copied.Stat().HasValue());
        EXPECT_EQ(lookup, copied.Metadata().LookupName());
    }
    EXPECT_EQ(before, OpenDescriptors());
    EXPECT_GT(context.nativeCloses, closesBefore);
    EXPECT_EQ(0u, context.failedNativeCloses);
}

TEST(FilesystemCollectionAllocationTest, ApplyAllocationFailuresNeverPublishPartialState)
{
    using ComplianceEngine::Filesystem::Path;
    AllocationCloseContext context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    const std::string directory = context.GetTempdirPath();
    const std::string child = context.MakeTempfile("pinned");
    const std::string name = child.substr(child.find_last_of('/') + 1);
    ComplianceEngine::Filesystem::ResolverLimits limits;
    limits.shared.retainedBytes = 262144;
    Path::Policy policy;
    policy.mounts = ComplianceEngine::Filesystem::MountPolicy::CrossMounts;
    auto prepare = [&]() -> ComplianceEngine::Result<Path> {
        auto opened = Path::Make(context, directory, policy, limits);
        if (!opened.HasValue())
            return std::move(opened).Error();
        if (!opened.Value().Is<Path>())
            return ComplianceEngine::Error("Fixture root missing", ENOENT);
        Path path = ComplianceEngine::As<Path>(std::move(opened.Value()));
        auto frozen = path.Freeze();
        if (!frozen.HasValue())
            return std::move(frozen).Error();
        return path;
    };
    auto control = prepare();
    ASSERT_TRUE(control.HasValue()) << control.Error().message;
    auto controlStep = control.Value().Resolve(name, policy);
    ASSERT_TRUE(controlStep.HasValue());
    ASSERT_TRUE(controlStep.Value().Is<Path::Step>());
    freezeAllocationAttempts = 0;
    failFreezeAt = 0;
    countFreezeAllocations = true;
    auto applied = control.Value().Apply(std::move(ComplianceEngine::As<Path::Step>(controlStep.Value())));
    countFreezeAllocations = false;
    ASSERT_TRUE(applied.HasValue()) << applied.Error().message;
    const std::size_t allocations = freezeAllocationAttempts;
    ASSERT_GT(allocations, 2u); // inverse, vector, names, immutable State publication
    for (std::size_t failure = 1; failure <= allocations; ++failure)
    {
        SCOPED_TRACE(failure);
        const auto beforeDescriptors = OpenDescriptors();
        {
            auto opened = prepare();
            ASSERT_TRUE(opened.HasValue());
            Path path = std::move(opened).Value();
            auto resolved = path.Resolve(name, policy);
            ASSERT_TRUE(resolved.HasValue());
            ASSERT_TRUE(resolved.Value().Is<Path::Step>());
            Path::Step step = ComplianceEngine::As<Path::Step>(std::move(resolved.Value()));
            const std::string oldName = path.ToString();
            const auto oldSize = path.Size();
            const auto oldIdentity = path.Leaf().Metadata().Stat().st_ino;
            freezeAllocationAttempts = 0;
            failFreezeAt = failure;
            countFreezeAllocations = true;
            EXPECT_THROW((void)path.Apply(std::move(step)), std::bad_alloc);
            countFreezeAllocations = false;
            EXPECT_EQ(failure, freezeAllocationAttempts);
            EXPECT_EQ(oldName, path.ToString());
            EXPECT_EQ(oldSize, path.Size());
            EXPECT_EQ(oldIdentity, path.Leaf().Metadata().Stat().st_ino);
            EXPECT_TRUE(step.Target().Stat().HasValue());
        }
        EXPECT_EQ(beforeDescriptors, OpenDescriptors());
    }
    failFreezeAt = 0;
}

TEST(FilesystemCollectionAllocationTest, FTWFactoryAllocationFaultDoesNotConsumeSelectedRoot)
{
    using ComplianceEngine::Filesystem::Path;
    AllocationCloseContext context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    const std::string directory = context.GetTempdirPath();
    ComplianceEngine::Filesystem::ResolverLimits limits;
    limits.shared.retainedBytes = 262144;
    Path::Policy policy;
    policy.mounts = ComplianceEngine::Filesystem::MountPolicy::CrossMounts;
    auto makeRoot = [&]() -> ComplianceEngine::Result<Path> {
        auto opened = Path::Make(context, directory, policy, limits);
        if (!opened.HasValue())
            return std::move(opened).Error();
        if (!opened.Value().Is<Path>())
            return ComplianceEngine::Error("Fixture root absent", ENOENT);
        return ComplianceEngine::As<Path>(std::move(opened.Value()));
    };
    ComplianceEngine::Filesystem::FilesystemTraversalPolicy traversal;
    traversal.scope = ComplianceEngine::Filesystem::FilesystemScope::All;
    auto root = makeRoot();
    ASSERT_TRUE(root.HasValue()) << root.Error().message;
    // FTW takes the reporting name by value. Copying directory at the call
    // site would allocate before the factory's bad_alloc handler can run.
    std::string controlReportingName = directory;
    freezeAllocationAttempts = 0;
    failFreezeAt = 0;
    countFreezeAllocations = true;
    auto control = ComplianceEngine::Filesystem::FTW::Files(std::move(root).Value(), std::move(controlReportingName), traversal);
    countFreezeAllocations = false;
    ASSERT_TRUE(control.HasValue()) << control.Error().message;
    const std::size_t allocations = freezeAllocationAttempts;
    ASSERT_GT(allocations, 2u);
    control.Value().Stop();
    // Only the first pre-cursor Freeze allocation can be faulted safely here.
    // Later ordinal faults could throw from a noexcept native/GMock seam;
    // frame, inverse and post-Apply failures need a narrow traversal hook.
    for (const std::size_t failure : {std::size_t{1}})
    {
        SCOPED_TRACE(failure);
        const std::size_t before = OpenDescriptors();
        std::size_t retainedDescriptors = 0;
        std::size_t closesBefore = 0;
        {
            auto selected = makeRoot();
            ASSERT_TRUE(selected.HasValue()) << selected.Error().message;
            Path rootPath = std::move(selected).Value();
            const auto inode = rootPath.Leaf().Metadata().Stat().st_ino;
            retainedDescriptors = rootPath.RetainedDescriptors();
            closesBefore = context.nativeCloses;
            std::string reportingName = directory; // Allocate before arming, then transfer without a copy.
            freezeAllocationAttempts = 0;
            failFreezeAt = failure;
            countFreezeAllocations = true;
            auto failed = ComplianceEngine::Filesystem::FTW::Files(std::move(rootPath), std::move(reportingName), traversal);
            countFreezeAllocations = false;
            ASSERT_FALSE(failed.HasValue());
            EXPECT_EQ(ENOMEM, failed.Error().code);
            EXPECT_EQ(failure, freezeAllocationAttempts);
            EXPECT_EQ(directory, rootPath.ToString()); // Path move-as-copy retains its source.
            EXPECT_EQ(inode, rootPath.Leaf().Metadata().Stat().st_ino);
            EXPECT_TRUE(rootPath.Leaf().Stat().HasValue());
            EXPECT_EQ(closesBefore, context.nativeCloses); // The original selected root still owns its pins.
        }
        EXPECT_EQ(before, OpenDescriptors());
        EXPECT_EQ(retainedDescriptors, context.nativeCloses - closesBefore); // Each pin closes once on release.
        EXPECT_EQ(0u, context.actualNativeCloseFailures);
    }
    failFreezeAt = 0;
}

TEST(FilesystemCollectionAllocationTest, FTWRangeAndResultTransfersDoNotAllocate)
{
    using ComplianceEngine::Filesystem::FTW::FileRange;
    static_assert(std::is_nothrow_move_constructible<FileRange>::value, "FTW range move must not allocate");
    AllocationCloseContext context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    const std::string directory = context.GetTempdirPath();
    ComplianceEngine::Filesystem::FilesystemCollectionRequest request(directory, ComplianceEngine::Filesystem::FilesystemRootKind::Directory);
    auto opened = ComplianceEngine::Filesystem::FTW::Files(request, context);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    struct ResetFaultOnExit
    {
        ~ResetFaultOnExit()
        {
            faultTransfers = false;
        }
    } reset;
    faultTransfers = true;
    FileRange range(std::move(opened).Value());
    ComplianceEngine::Result<FileRange> returned(std::move(range));
    ComplianceEngine::Result<FileRange> transferred(std::move(returned));
    faultTransfers = false;
    EXPECT_EQ(0u, transferAllocations);
    EXPECT_FALSE(range.RootExists());
    EXPECT_TRUE(transferred.HasValue());
    EXPECT_TRUE(transferred.Value().RootExists());
    transferred.Value().Stop();
}

TEST(FilesystemCollectionAllocationTest, FTWFrameInverseAndPublicationFaultsAbortWithoutLosingHeldPins)
{
    using ComplianceEngine::Filesystem::FTW::Files;
    PreparedTraversalFixture fixture;
    ResetCheckpointOnExit resetCheckpoint;
    for (const TestCheckpoint site : {TestCheckpoint::FrameReserve, TestCheckpoint::InversePreparation, TestCheckpoint::AfterApply, TestCheckpoint::BeforeOffer})
    {
        SCOPED_TRACE(static_cast<unsigned>(site));
        const auto descriptorsBefore = OpenDescriptors();
        const auto closesBefore = fixture.context.nativeCloses;
        const auto closeFailuresBefore = fixture.context.actualNativeCloseFailures;
        {
            auto opened = Files(fixture.request, fixture.context);
            ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
            auto source = std::move(opened).Value();
            auto range = std::move(source);
            EXPECT_FALSE(source.RootExists());
            source.Stop(); // A moved-from range cannot close the live traversal.
            auto iter = range.begin();
            ASSERT_NE(iter, range.end());
            ASSERT_TRUE(iter->HasValue());
            ASSERT_EQ(fixture.root, iter->Value().path);
            auto retainedPin = iter->Value().LiveComponent();
            ASSERT_TRUE(retainedPin.HasValue());
            const auto inode = iter->Value().metadata.st_ino;

            checkpointHits = 0;
            inverseAllocationFailures = 0;
            armedCheckpoint = static_cast<unsigned>(site);
            ++iter; // Descend into branch; no fault is armed in a native mock.
            ASSERT_NE(iter, range.end());
            ASSERT_FALSE(iter->HasValue());
            EXPECT_EQ(ENOMEM, iter->Error().code);
            EXPECT_EQ(1u, checkpointHits);
            EXPECT_EQ(site == TestCheckpoint::InversePreparation ? 1u : 0u, inverseAllocationFailures);
            EXPECT_FALSE(faultInverseAllocation);
            EXPECT_EQ(0u, armedCheckpoint);
            ++iter;
            EXPECT_EQ(range.end(), iter);          // Exactly one delivered error.
            EXPECT_EQ(range.end(), range.begin()); // Aborted, never resumes.
            range.Stop();
            range.Stop();
            auto stat = retainedPin.Value().Stat();
            ASSERT_TRUE(stat.HasValue()) << stat.Error().message;
            EXPECT_EQ(inode, stat.Value().st_ino);
            retainedPin.Reset();
        }
        EXPECT_GT(fixture.context.nativeCloses, closesBefore);
        EXPECT_EQ(closeFailuresBefore, fixture.context.actualNativeCloseFailures); // No double close.
        EXPECT_EQ(descriptorsBefore, OpenDescriptors());
    }
}

TEST(FilesystemCollectionAllocationTest, FTWFailedInverseDeliversOneErrorAndRejectsPartialCollection)
{
    using ComplianceEngine::Filesystem::FTW::Files;
    PreparedTraversalFixture fixture;
    ResetCheckpointOnExit resetCheckpoint;
    const auto descriptorsBefore = OpenDescriptors();
    const auto closeFailuresBefore = fixture.context.actualNativeCloseFailures;
    {
        auto opened = Files(fixture.request, fixture.context);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        auto range = std::move(opened).Value();
        auto iter = range.begin();
        ASSERT_NE(iter, range.end());
        ASSERT_TRUE(iter->HasValue());
        EXPECT_EQ(fixture.root, iter->Value().path);
        ++iter;
        ASSERT_NE(iter, range.end());
        ASSERT_TRUE(iter->HasValue());
        EXPECT_EQ(fixture.directory, iter->Value().path);
        ++iter;
        ASSERT_NE(iter, range.end());
        ASSERT_TRUE(iter->HasValue());
        ASSERT_EQ(fixture.file, iter->Value().path);
        auto retainedPin = iter->Value().LiveComponent();
        ASSERT_TRUE(retainedPin.HasValue());
        const auto inode = iter->Value().metadata.st_ino;
        checkpointHits = 0;
        fixture.context.reportNativeCloseFailure = true;
        armedCheckpoint = static_cast<unsigned>(TestCheckpoint::InverseRestore);
        ++iter; // Exhaust branch, then reject its inverse with ESTALE.
        ASSERT_NE(iter, range.end());
        ASSERT_FALSE(iter->HasValue());
        EXPECT_EQ(ESTALE, iter->Error().code);
        EXPECT_EQ(1u, checkpointHits);
        EXPECT_EQ(0u, armedCheckpoint);
        ++iter;
        EXPECT_EQ(range.end(), iter);
        EXPECT_EQ(range.end(), range.begin());
        range.Stop();
        EXPECT_GT(fixture.context.failedNativeCloses, 0u);
        fixture.context.reportNativeCloseFailure = false;
        ASSERT_EQ(0, ::unlink(fixture.file.c_str()));
        auto stat = retainedPin.Value().Stat();
        ASSERT_TRUE(stat.HasValue()) << stat.Error().message;
        EXPECT_EQ(inode, stat.Value().st_ino); // Original file pin outlives removal/range.
        retainedPin.Reset();
    }
    EXPECT_EQ(descriptorsBefore, OpenDescriptors());
    EXPECT_EQ(closeFailuresBefore, fixture.context.actualNativeCloseFailures);

    // Recreate fixture content before starting the independent collection.
    std::ofstream output(fixture.file);
    output << "content";
    output.close();
    ASSERT_TRUE(output);
    checkpointHits = 0;
    armedCheckpoint = static_cast<unsigned>(TestCheckpoint::InverseRestore);
    auto collected = ComplianceEngine::Filesystem::CollectFilesystem(fixture.request, fixture.context);
    ASSERT_FALSE(collected.HasValue());
    EXPECT_EQ(ESTALE, collected.Error().code);
    EXPECT_EQ(1u, checkpointHits);
    EXPECT_EQ(0u, armedCheckpoint);
    EXPECT_EQ(descriptorsBefore, OpenDescriptors());
    EXPECT_EQ(closeFailuresBefore, fixture.context.actualNativeCloseFailures);
}
