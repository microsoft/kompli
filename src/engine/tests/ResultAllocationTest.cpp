// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "../Result.h"

#include <cstddef>
#include <cstdlib>
#include <gtest/gtest.h>
#include <new>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

using Kompli::Error;
using Kompli::Result;

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

// Result<std::string> moves must stay nonthrowing, like those of every
// payload Result accepts.
static_assert(std::is_nothrow_move_constructible<Result<std::string>>::value, "Result<std::string> move construction is nonthrowing");
static_assert(std::is_nothrow_move_assignable<Result<std::string>>::value, "Result<std::string> move assignment is nonthrowing");

struct FaultOutcome
{
    bool caught = false;
    std::size_t attempts = 0;
};

// Runs `operation` under an armed AllocationProbe (fails the first
// allocation) and reports whether it threw std::bad_alloc, plus the number
// of allocation attempts made before the probe disarms.
template <typename Operation>
FaultOutcome RunUnderFault(Operation operation)
{
    FaultOutcome outcome;
    AllocationProbe probe(true);
    try
    {
        operation();
    }
    catch (const std::bad_alloc&)
    {
        outcome.caught = true;
    }
    outcome.attempts = probe.Attempts();
    return outcome;
}

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

TEST(ResultAllocationTest, StringCopyAssignmentKeepsValueDestinationWhenValueSourceCopyFails)
{
    Result<std::string> destination(std::string(256, char(100)));
    Result<std::string> source(std::string(256, char(115)));
    FaultOutcome outcome = RunUnderFault([&]() { destination = source; });
    EXPECT_TRUE(outcome.caught);
    EXPECT_EQ(1u, outcome.attempts);
    ASSERT_TRUE(destination.HasValue());
    EXPECT_EQ(std::string(256, char(100)), destination.Value());
    EXPECT_THROW(destination.Error(), std::logic_error);
    ASSERT_TRUE(source.HasValue());
    EXPECT_EQ(std::string(256, char(115)), source.Value());
}

TEST(ResultAllocationTest, StringCopyAssignmentKeepsValueDestinationWhenErrorSourceCopyFails)
{
    Result<std::string> destination(std::string(256, char(100)));
    Result<std::string> source(Error(std::string(256, char(115)), 41));
    FaultOutcome outcome = RunUnderFault([&]() { destination = source; });
    EXPECT_TRUE(outcome.caught);
    EXPECT_EQ(1u, outcome.attempts);
    ASSERT_TRUE(destination.HasValue());
    EXPECT_EQ(std::string(256, char(100)), destination.Value());
    EXPECT_THROW(destination.Error(), std::logic_error);
    ASSERT_FALSE(source.HasValue());
    EXPECT_EQ(41, source.Error().code);
    EXPECT_EQ(std::string(256, char(115)), source.Error().message);
}

TEST(ResultAllocationTest, StringCopyAssignmentKeepsErrorDestinationWhenValueSourceCopyFails)
{
    Result<std::string> destination(Error(std::string(256, char(100)), 27));
    Result<std::string> source(std::string(256, char(115)));
    FaultOutcome outcome = RunUnderFault([&]() { destination = source; });
    EXPECT_TRUE(outcome.caught);
    EXPECT_EQ(1u, outcome.attempts);
    ASSERT_FALSE(destination.HasValue());
    EXPECT_EQ(27, destination.Error().code);
    EXPECT_EQ(std::string(256, char(100)), destination.Error().message);
    EXPECT_THROW(destination.Value(), std::logic_error);
    ASSERT_TRUE(source.HasValue());
    EXPECT_EQ(std::string(256, char(115)), source.Value());
}

TEST(ResultAllocationTest, StringCopyAssignmentKeepsErrorDestinationWhenErrorSourceCopyFails)
{
    Result<std::string> destination(Error(std::string(256, char(100)), 27));
    Result<std::string> source(Error(std::string(256, char(115)), 41));
    FaultOutcome outcome = RunUnderFault([&]() { destination = source; });
    EXPECT_TRUE(outcome.caught);
    EXPECT_EQ(1u, outcome.attempts);
    ASSERT_FALSE(destination.HasValue());
    EXPECT_EQ(27, destination.Error().code);
    EXPECT_EQ(std::string(256, char(100)), destination.Error().message);
    EXPECT_THROW(destination.Value(), std::logic_error);
    ASSERT_FALSE(source.HasValue());
    EXPECT_EQ(41, source.Error().code);
    EXPECT_EQ(std::string(256, char(115)), source.Error().message);
}

TEST(ResultAllocationTest, StringMoveConstructionAndAssignmentNeverAllocate)
{
    // Move the freshly constructed object into a persistent variable (via a
    // second zero-allocation move) so its state can be read back after the
    // probe disarms -- constructing a comparison string inside the armed
    // window would itself allocate and be mistaken for the operation's own.
    Result<std::string> constructedFromValue(Error("placeholder"));
    Result<std::string> valueSource(std::string(256, char(115)));
    FaultOutcome moveConstructValue = RunUnderFault([&]() {
        Result<std::string> moved(std::move(valueSource));
        constructedFromValue = std::move(moved);
    });
    EXPECT_FALSE(moveConstructValue.caught);
    EXPECT_EQ(0u, moveConstructValue.attempts);
    ASSERT_TRUE(constructedFromValue.HasValue());
    EXPECT_EQ(std::string(256, char(115)), constructedFromValue.Value());

    Result<std::string> constructedFromError(Error("placeholder"));
    Result<std::string> errorSource(Error(std::string(256, char(115)), 41));
    FaultOutcome moveConstructError = RunUnderFault([&]() {
        Result<std::string> moved(std::move(errorSource));
        constructedFromError = std::move(moved);
    });
    EXPECT_FALSE(moveConstructError.caught);
    EXPECT_EQ(0u, moveConstructError.attempts);
    ASSERT_FALSE(constructedFromError.HasValue());
    EXPECT_EQ(41, constructedFromError.Error().code);
    EXPECT_EQ(std::string(256, char(115)), constructedFromError.Error().message);

    Result<std::string> valueSourceForAssignment(std::string(256, char(115)));
    Result<std::string> valueDestination(std::string(256, char(100)));
    FaultOutcome moveAssignValue = RunUnderFault([&]() { valueDestination = std::move(valueSourceForAssignment); });
    EXPECT_FALSE(moveAssignValue.caught);
    EXPECT_EQ(0u, moveAssignValue.attempts);
    ASSERT_TRUE(valueDestination.HasValue());
    EXPECT_EQ(std::string(256, char(115)), valueDestination.Value());

    Result<std::string> errorSourceForAssignment(Error(std::string(256, char(115)), 41));
    Result<std::string> errorDestination(Error(std::string(256, char(100)), 27));
    FaultOutcome moveAssignError = RunUnderFault([&]() { errorDestination = std::move(errorSourceForAssignment); });
    EXPECT_FALSE(moveAssignError.caught);
    EXPECT_EQ(0u, moveAssignError.attempts);
    ASSERT_FALSE(errorDestination.HasValue());
    EXPECT_EQ(41, errorDestination.Error().code);
    EXPECT_EQ(std::string(256, char(115)), errorDestination.Error().message);
}
