// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Optional.h"

#include <gtest/gtest.h>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>

using ComplianceEngine::Optional;

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

static_assert(std::is_copy_constructible<Optional<int>>::value, "copyable Optional must be copy constructible");
static_assert(std::is_copy_assignable<Optional<int>>::value, "copyable Optional must be copy assignable");
static_assert(!std::is_copy_constructible<Optional<std::unique_ptr<int>>>::value, "move-only Optional must not be copy constructible");
static_assert(!std::is_copy_assignable<Optional<std::unique_ptr<int>>>::value, "move-only Optional must not be copy assignable");
static_assert(std::is_copy_assignable<Optional<CopyConstructibleNotAssignable>>::value, "Optional assignment reconstructs its value");
static_assert(std::is_same<decltype(std::declval<Optional<int>&&>().Value()), int>::value, "rvalue Optional access returns by value");
static_assert(!noexcept(std::declval<Optional<int>&&>().Value()), "checked rvalue Optional access may throw");
static_assert(noexcept(std::declval<const Optional<int>&>().ValueOr(std::declval<const int&>())), "nonthrowing scalar ValueOr remains nonthrowing");
static_assert(std::is_nothrow_copy_constructible<ThrowingFallbackMove>::value, "test isolates a throwing fallback move");
static_assert(!std::is_nothrow_move_constructible<ThrowingFallbackMove>::value, "test fallback move can throw");
static_assert(!noexcept(std::declval<const Optional<ThrowingFallbackMove>&>().ValueOr(std::declval<const ThrowingFallbackMove&>())),
    "const ValueOr must permit a fallback move to throw");
} // namespace

class OptionalTest : public ::testing::Test
{
};

TEST_F(OptionalTest, DefaultContructor)
{
    Optional<int> opt;
    ASSERT_FALSE(opt.HasValue());
}

TEST_F(OptionalTest, ValueContructor)
{
    Optional<int> opt(42);
    ASSERT_TRUE(opt.HasValue());
    ASSERT_EQ(opt.Value(), 42);

    opt = Optional<int>{};
    ASSERT_FALSE(opt.HasValue());
}

TEST_F(OptionalTest, CopyContructor)
{
    Optional<int> opt1(42);
    Optional<int> opt2(opt1);
    ASSERT_TRUE(opt1.HasValue());
    ASSERT_TRUE(opt2.HasValue());
    ASSERT_EQ(opt2.Value(), 42);
}

TEST_F(OptionalTest, MoveContructor)
{
    Optional<int> opt1(42);
    Optional<int> opt2(std::move(opt1));
#ifndef __clang_analyzer__
    ASSERT_FALSE(opt1.HasValue());
#endif
    ASSERT_TRUE(opt2.HasValue());
    ASSERT_EQ(opt2.Value(), 42);
}

TEST_F(OptionalTest, CopyAssignment)
{
    Optional<int> opt1(42);
    Optional<int> opt2;
    opt2 = opt1;
    ASSERT_TRUE(opt1.HasValue());
    ASSERT_TRUE(opt2.HasValue());
    ASSERT_EQ(opt2.Value(), 42);
}

TEST_F(OptionalTest, MoveAssignment)
{
    Optional<int> opt1(42);
    Optional<int> opt2;
    opt2 = std::move(opt1);
#ifndef __clang_analyzer__
    ASSERT_FALSE(opt1.HasValue());
#endif
    ASSERT_TRUE(opt2.HasValue());
    ASSERT_EQ(opt2.Value(), 42);
}

TEST_F(OptionalTest, ValueAssignment)
{
    Optional<int> opt;
    opt = 42;
    ASSERT_TRUE(opt.HasValue());
    ASSERT_EQ(opt.Value(), 42);
}

TEST_F(OptionalTest, ReferenceReturned)
{
    Optional<int> opt(42);
    opt.Value() = 43;
    ASSERT_TRUE(opt.HasValue());
    ASSERT_EQ(opt.Value(), 43);
}

TEST_F(OptionalTest, BoolConversion)
{
    Optional<std::string> opt;
    ASSERT_FALSE(opt);
    opt = "foo";
    ASSERT_TRUE(opt);
}

TEST_F(OptionalTest, ValueOr)
{
    Optional<int> opt;
    ASSERT_EQ(opt.ValueOr(42), 42);
    opt = 43;
    ASSERT_EQ(opt.ValueOr(42), 43);
}

TEST_F(OptionalTest, ConstValueOrPropagatesFallbackMoveAndCopiesPresentValue)
{
    FallbackState state;
    const ThrowingFallbackMove fallback(state, 42);
    const Optional<ThrowingFallbackMove> empty{};
    state.throwOnMove = true;
    EXPECT_THROW(empty.ValueOr(fallback), std::runtime_error);
    EXPECT_EQ(1, state.copies);
    EXPECT_EQ(1, state.moves);

    state.throwOnMove = false;
    const Optional<ThrowingFallbackMove> present(ThrowingFallbackMove(state, 7));
    const int movesBefore = state.moves;
    const int copiesBefore = state.copies;
    state.throwOnMove = true;
    EXPECT_EQ(7, present.ValueOr(fallback).value);
    EXPECT_EQ(copiesBefore + 2, state.copies);
    EXPECT_EQ(movesBefore, state.moves);
}

TEST_F(OptionalTest, Reset)
{
    Optional<int> opt(42);
    ASSERT_TRUE(opt.HasValue());
    opt.Reset();
    ASSERT_FALSE(opt.HasValue());
}

TEST_F(OptionalTest, ArrowOperator)
{
    auto opt = Optional<std::string>("foo");
    ASSERT_TRUE(opt.HasValue());
    ASSERT_EQ(opt->size(), 3u);
    opt->append("bar");
    ASSERT_EQ(opt->size(), 6u);
}

TEST_F(OptionalTest, EmptyRvalueValueThrows)
{
    Optional<int> empty;
    EXPECT_THROW(std::move(empty).Value(), std::logic_error);
}

TEST_F(OptionalTest, CopyAssignmentReconstructsNonassignableValue)
{
    Optional<CopyConstructibleNotAssignable> source(CopyConstructibleNotAssignable(42));
    Optional<CopyConstructibleNotAssignable> destination(CopyConstructibleNotAssignable(7));
    destination = source;
    EXPECT_EQ(destination.Value().number, 42);
    auto& alias = destination;
    destination = alias;
    EXPECT_EQ(destination.Value().number, 42);
}

TEST_F(OptionalTest, MoveOnlyValueAndEmptyTransitions)
{
    Optional<std::unique_ptr<int>> source(std::unique_ptr<int>(new int(42)));
    Optional<std::unique_ptr<int>> moved(std::move(source));
    EXPECT_FALSE(source.HasValue());
    ASSERT_TRUE(moved.HasValue());
    EXPECT_EQ(*moved.Value(), 42);

    Optional<std::unique_ptr<int>> destination(std::unique_ptr<int>(new int(7)));
    destination = std::move(moved);
    EXPECT_FALSE(moved.HasValue());
    ASSERT_TRUE(destination.HasValue());
    EXPECT_EQ(*destination.Value(), 42);
    destination = Optional<std::unique_ptr<int>>{};
    EXPECT_FALSE(destination.HasValue());
}
