// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <cerrno>
#include <cstddef>
#include <filesystem/FilesystemCollection.hpp>
#include <gtest/gtest.h>
#include <new>
#include <string>

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

extern "C" void* __real__Znwm(std::size_t bytes);
extern "C" void* __wrap__Znwm(std::size_t bytes)
{
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
