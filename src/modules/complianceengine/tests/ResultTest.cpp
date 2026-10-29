// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Result.h"

#include <gtest/gtest.h>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>

using ComplianceEngine::Error;
using ComplianceEngine::Result;

namespace
{
struct CopyConstructibleNotAssignable
{
    explicit CopyConstructibleNotAssignable(int number)
        : number(number)
    {
    }
    CopyConstructibleNotAssignable(const CopyConstructibleNotAssignable&) = default;
    CopyConstructibleNotAssignable(CopyConstructibleNotAssignable&&) = default;
    CopyConstructibleNotAssignable& operator=(const CopyConstructibleNotAssignable&) = delete;
    CopyConstructibleNotAssignable& operator=(CopyConstructibleNotAssignable&&) = delete;
    int number;
};

struct FallbackState
{
    int copies = 0;
    int moves = 0;
    bool throwOnMove = false;
};

struct ThrowingFallbackMove
{
    FallbackState* state;
    int value;

    ThrowingFallbackMove(FallbackState& counters, int number) noexcept
        : state(&counters),
          value(number)
    {
    }

    ThrowingFallbackMove(const ThrowingFallbackMove& other) noexcept
        : state(other.state),
          value(other.value)
    {
        ++state->copies;
    }

    ThrowingFallbackMove(ThrowingFallbackMove&& other)
        : state(other.state),
          value(other.value)
    {
        ++state->moves;
        if (state->throwOnMove)
        {
            throw std::runtime_error("fallback move");
        }
    }
};

static_assert(std::is_copy_constructible<Result<int>>::value, "copyable Result must be copy constructible");
static_assert(std::is_copy_assignable<Result<int>>::value, "copyable Result must be copy assignable");
static_assert(!std::is_copy_constructible<Result<std::unique_ptr<int>>>::value, "move-only Result must not be copy constructible");
static_assert(!std::is_copy_assignable<Result<std::unique_ptr<int>>>::value, "move-only Result must not be copy assignable");
static_assert(std::is_copy_assignable<Result<CopyConstructibleNotAssignable>>::value, "Result assignment reconstructs its value");
static_assert(std::is_same<decltype(std::declval<Result<int>&&>().Value()), int>::value, "rvalue Result access returns by value");
static_assert(noexcept(std::declval<const Result<int>&>().ValueOr(std::declval<const int&>())), "nonthrowing scalar ValueOr remains nonthrowing");
static_assert(std::is_nothrow_copy_constructible<ThrowingFallbackMove>::value, "test isolates a throwing fallback move");
static_assert(!std::is_nothrow_move_constructible<ThrowingFallbackMove>::value, "test fallback move can throw");
static_assert(!noexcept(std::declval<const Result<ThrowingFallbackMove>&>().ValueOr(std::declval<const ThrowingFallbackMove&>())),
    "const ValueOr must permit a fallback move to throw");
} // namespace

class ResultTest : public ::testing::Test
{
};

TEST_F(ResultTest, ErrorContructor)
{
    Result<int> result(Error("error"));
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, std::string("error"));
}

TEST_F(ResultTest, ValueContructor)
{
    Result<int> result(42);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), 42);

    result = Result<int>{Error("error")};
    ASSERT_FALSE(result.HasValue());
}

TEST_F(ResultTest, CopyContructor)
{
    Result<int> result1(42);
    Result<int> result2(result1);
    ASSERT_TRUE(result1.HasValue());
    ASSERT_TRUE(result2.HasValue());
    ASSERT_EQ(result2.Value(), 42);
}

TEST_F(ResultTest, MoveContructor)
{
    Result<int> result1(42);
    Result<int> result2(std::move(result1));
#ifndef __clang_analyzer__
    ASSERT_FALSE(result1.HasValue());
#endif
    ASSERT_TRUE(result2.HasValue());
    ASSERT_EQ(result2.Value(), 42);
}

TEST_F(ResultTest, CopyAssignment)
{
    Result<int> result1(42);
    Result<int> result2(Error("old error"));
    result2 = result1;
    ASSERT_TRUE(result1.HasValue());
    ASSERT_TRUE(result2.HasValue());
    ASSERT_EQ(result2.Value(), 42);

    Result<int> error(Error("new error"));
    result2 = error;
    ASSERT_FALSE(result2.HasValue());
    ASSERT_EQ(result2.Error().message, "new error");
    ASSERT_FALSE(error.HasValue());
    auto& result2Alias = result2;
    result2 = result2Alias;
    ASSERT_EQ(result2.Error().message, "new error");

    error = result1;
    ASSERT_TRUE(error.HasValue());
    ASSERT_EQ(error.Value(), 42);
    auto& errorAlias = error;
    error = errorAlias;
    ASSERT_EQ(error.Value(), 42);
}

TEST_F(ResultTest, MoveAssignment)
{
    Result<int> result1(42);
    Result<int> result2(Error("old error"));
    result2 = std::move(result1);
#ifndef __clang_analyzer__
    ASSERT_FALSE(result1.HasValue());
#endif
    ASSERT_TRUE(result2.HasValue());
    ASSERT_EQ(result2.Value(), 42);

    result1 = Result<int>(Error("new error"));
    result2 = std::move(result1);
    ASSERT_FALSE(result2.HasValue());
    ASSERT_EQ(result2.Error().message, "new error");
    auto& result2Alias = result2;
    result2 = std::move(result2Alias);
    ASSERT_EQ(result2.Error().message, "new error");

    result1 = Result<int>(7);
    result2 = std::move(result1);
    ASSERT_TRUE(result2.HasValue());
    ASSERT_EQ(result2.Value(), 7);
}

TEST_F(ResultTest, ValueAssignment)
{
    Result<int> result(Error("error"));
    result = 42;
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), 42);
}

TEST_F(ResultTest, ValueReference)
{
    Result<int> result(42);
    result.Value() = 43;
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), 43);
}

TEST_F(ResultTest, ErrorReference)
{
    auto result = Result<int>(Error("error"));
    result.Error().message = "ERROR";
    ASSERT_EQ(result.Error().message, "ERROR");
}

TEST_F(ResultTest, BoolConversion)
{
    Result<std::string> result(Error("error"));
    ASSERT_FALSE(result);
    result = std::string("foo");
    ASSERT_TRUE(result);
}

TEST_F(ResultTest, ValueOr)
{
    Result<int> result(Error("error"));
    ASSERT_EQ(result.ValueOr(42), 42);
    result = 43;
    ASSERT_EQ(result.ValueOr(42), 43);
}

TEST_F(ResultTest, ConstValueOrPropagatesFallbackMoveAndCopiesPresentValue)
{
    FallbackState state;
    const ThrowingFallbackMove fallback(state, 42);
    const Result<ThrowingFallbackMove> error(Error("error"));
    state.throwOnMove = true;
    EXPECT_THROW(error.ValueOr(fallback), std::runtime_error);
    EXPECT_EQ(1, state.copies);
    EXPECT_EQ(1, state.moves);

    state.throwOnMove = false;
    const Result<ThrowingFallbackMove> present(ThrowingFallbackMove(state, 7));
    const int movesBefore = state.moves;
    const int copiesBefore = state.copies;
    state.throwOnMove = true;
    EXPECT_EQ(7, present.ValueOr(fallback).value);
    EXPECT_EQ(copiesBefore + 2, state.copies);
    EXPECT_EQ(movesBefore, state.moves);
}

TEST_F(ResultTest, ArrowOperator)
{
    auto result = Result<std::string>("foo");
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result->size(), 3u);
    result->append("bar");
    ASSERT_EQ(result->size(), 6u);
}

TEST_F(ResultTest, CopyAssignmentReconstructsNonassignableValue)
{
    Result<CopyConstructibleNotAssignable> source(CopyConstructibleNotAssignable(42));
    Result<CopyConstructibleNotAssignable> destination(Error("old error"));
    Result<CopyConstructibleNotAssignable> copied(source);
    EXPECT_EQ(copied.Value().number, 42);
    destination = source;
    EXPECT_EQ(destination.Value().number, 42);
    auto& alias = destination;
    destination = alias;
    EXPECT_EQ(destination.Value().number, 42);
}

TEST_F(ResultTest, MoveOnlyValueAndErrorTransitions)
{
    Result<std::unique_ptr<int>> source(std::unique_ptr<int>(new int(42)));
    Result<std::unique_ptr<int>> moved(std::move(source));
    EXPECT_FALSE(source.HasValue());
    ASSERT_TRUE(moved.HasValue());
    EXPECT_EQ(*moved.Value(), 42);

    Result<std::unique_ptr<int>> destination(Error("old error"));
    destination = std::move(moved);
    EXPECT_FALSE(moved.HasValue());
    ASSERT_TRUE(destination.HasValue());
    EXPECT_EQ(*destination.Value(), 42);
    Result<std::unique_ptr<int>> error(Error("new error"));
    destination = std::move(error);
    ASSERT_FALSE(destination.HasValue());
    EXPECT_EQ(destination.Error().message, "new error");
}
