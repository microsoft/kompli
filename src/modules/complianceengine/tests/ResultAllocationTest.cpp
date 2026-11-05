// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "../src/lib/Result.h"

#include <cstddef>
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
} // namespace

extern "C" void* __real__Znwm(std::size_t bytes);
extern "C" void* __wrap__Znwm(std::size_t bytes)
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
    return __real__Znwm(bytes);
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
