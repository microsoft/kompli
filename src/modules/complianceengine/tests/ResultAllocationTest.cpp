// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "../src/lib/Result.h"

#include <cstddef>
#include <cstdlib>
#include <gtest/gtest.h>
#include <new>
#include <string>
#include <type_traits>
#include <utility>

using ComplianceEngine::Error;
using ComplianceEngine::Result;

namespace
{
// Intercept only this executable, and arm only around the operation under test.
thread_local bool g_countAllocations = false;
thread_local bool g_failNextAllocation = false;
thread_local std::size_t g_allocationAttempts = 0;

struct AllocationProbe
{
    explicit AllocationProbe(bool failFirst) noexcept
    {
        g_allocationAttempts = 0;
        g_failNextAllocation = failFirst;
        g_countAllocations = true;
    }

    ~AllocationProbe() noexcept
    {
        g_countAllocations = false;
        g_failNextAllocation = false;
    }

    std::size_t Attempts() const noexcept
    {
        return g_allocationAttempts;
    }
};

static_assert(std::is_nothrow_constructible<Error, int>::value, "code-only Error is nonthrowing");
static_assert(std::is_nothrow_constructible<Result<void>, Error&&>::value, "rvalue Error is nonthrowing");
static_assert(std::is_nothrow_move_constructible<Result<void>>::value, "move construction is nonthrowing");
static_assert(std::is_nothrow_move_assignable<Result<void>>::value, "move assignment is nonthrowing");
static_assert(noexcept(Result<void>::Success()), "success construction is nonthrowing");

// `-Wl,--wrap=_Znwm` only rewrites undefined references resolved among this
// executable's own linked objects. At -O2/-O3 (unsanitized GCC Release),
// `_GLIBCXX_ASSERTIONS` is off (only auto-enabled when `__OPTIMIZE__` is
// undefined), so libstdc++'s `_GLIBCXX_EXTERN_TEMPLATE` stays positive and
// `std::string`'s copy path (the allocation under test) resolves to the
// explicit instantiation already built into libstdc++.so; that internal
// `operator new` call is never rewritten, so the injected fault never fires.
// Replacing the global allocation functions is honored everywhere, including
// inside libstdc++.so, because the main executable's definitions take
// priority over a shared library's in the dynamic symbol scope. Forwarding
// to `std::malloc`/`std::free` keeps this ASan-compatible in the sanitized
// Debug trees: ASan intercepts `malloc`/`free` themselves (ahead of libc, by
// load order), so heap tracking still applies even though this replacement
// also takes priority over ASan's own `operator new`.
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
    if (g_countAllocations)
    {
        ++g_allocationAttempts;
        if (g_failNextAllocation)
        {
            g_failNextAllocation = false; // Disarm before unwinding or assertions.
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

TEST(ResultAllocationTest, FailureCopyAssignmentKeepsSuccessfulDestination)
{
    Result<void> source = Error(std::string(256, char(115)), 41);
    Result<void> destination = Result<void>::Success();
    bool caught = false;
    std::size_t attempts = 0;
    {
        AllocationProbe probe(true);
        try
        {
            destination = source;
        }
        catch (const std::bad_alloc&)
        {
            caught = true;
        }
        attempts = probe.Attempts();
    }
    EXPECT_TRUE(caught);
    EXPECT_EQ(1u, attempts);
    EXPECT_TRUE(destination.HasValue());
    ASSERT_FALSE(source.HasValue());
    EXPECT_EQ(41, source.Error().code);
    EXPECT_EQ(std::string(256, char(115)), source.Error().message);
}

TEST(ResultAllocationTest, FailureCopyAssignmentKeepsFailedDestination)
{
    Result<void> source = Error(std::string(256, char(115)), 41);
    Result<void> destination = Error(std::string(256, char(100)), 27);
    bool caught = false;
    std::size_t attempts = 0;
    {
        AllocationProbe probe(true);
        try
        {
            destination = source;
        }
        catch (const std::bad_alloc&)
        {
            caught = true;
        }
        attempts = probe.Attempts();
    }
    EXPECT_TRUE(caught);
    EXPECT_EQ(1u, attempts);
    ASSERT_FALSE(destination.HasValue());
    EXPECT_EQ(27, destination.Error().code);
    EXPECT_EQ(std::string(256, char(100)), destination.Error().message);
    ASSERT_FALSE(source.HasValue());
    EXPECT_EQ(41, source.Error().code);
    EXPECT_EQ(std::string(256, char(115)), source.Error().message);
}

TEST(ResultAllocationTest, SelfAssignmentDoesNotCopyUnderFault)
{
    Result<void> failure = Error(std::string(256, char(115)), 41);
    Result<void> success = Result<void>::Success();
    bool caught = false;
    std::size_t attempts = 0;
    {
        AllocationProbe probe(true);
        try
        {
            Result<void>& failureAlias = failure;
            Result<void>& successAlias = success;
            failure = failureAlias;
            success = successAlias;
        }
        catch (const std::bad_alloc&)
        {
            caught = true;
        }
        attempts = probe.Attempts();
    }
    EXPECT_FALSE(caught);
    EXPECT_EQ(0u, attempts);
    EXPECT_FALSE(failure.HasValue());
    EXPECT_EQ(41, failure.Error().code);
    EXPECT_EQ(std::string(256, char(115)), failure.Error().message);
    EXPECT_TRUE(success.HasValue());
}

TEST(ResultAllocationTest, StringCopyErrorAndResultConstructionPropagateBadAlloc)
{
    std::string message(256, char(115));
    Error source(message, 41);
    bool errorCaught = false;
    std::size_t errorAttempts = 0;
    {
        AllocationProbe probe(true);
        try
        {
            Error copied(source);
            (void)copied;
        }
        catch (const std::bad_alloc&)
        {
            errorCaught = true;
        }
        errorAttempts = probe.Attempts();
    }
    bool resultCaught = false;
    std::size_t resultAttempts = 0;
    {
        AllocationProbe probe(true);
        try
        {
            Result<void> copied(source);
            (void)copied;
        }
        catch (const std::bad_alloc&)
        {
            resultCaught = true;
        }
        resultAttempts = probe.Attempts();
    }
    EXPECT_TRUE(errorCaught);
    EXPECT_EQ(1u, errorAttempts);
    EXPECT_TRUE(resultCaught);
    EXPECT_EQ(1u, resultAttempts);
    EXPECT_EQ(41, source.code);
    EXPECT_EQ(message, source.message);
}

TEST(ResultAllocationTest, CodeOnlyErrorAndResultSuccessAndMovesNeverAllocate)
{
    Result<void> destination = Result<void>::Success();
    std::size_t attempts = 0;
    bool allStatesCorrect = false;
    {
        // If any operation allocates, the wrapper faults before it can return.
        AllocationProbe probe(true);
        Error codeOnly(17);
        Result<void> failed(std::move(codeOnly));
        Result<void> success = Result<void>::Success();
        Result<void> moved(std::move(failed));
        destination = std::move(moved);
        allStatesCorrect = !destination.HasValue() && (17 == destination.Error().code) && destination.Error().message.empty() && !failed.HasValue() &&
                           !moved.HasValue() && success.HasValue();
        attempts = probe.Attempts();
    }
    EXPECT_EQ(0u, attempts);
    EXPECT_TRUE(allStatesCorrect);
}
