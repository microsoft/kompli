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

struct ThrowingCopyState
{
    bool armed = false;
    int copies = 0;
};

// A noexcept move, and a copy that throws when its shared state is armed --
// isolates a throwing copy from the (always nonthrowing) move.
struct ThrowingCopy
{
    ThrowingCopyState* state;
    int value;

    ThrowingCopy(ThrowingCopyState& sharedState, int number) noexcept
        : state(&sharedState),
          value(number)
    {
    }

    ThrowingCopy(const ThrowingCopy& other)
        : state(other.state),
          value(other.value)
    {
        ++state->copies;
        if (state->armed)
        {
            throw std::runtime_error("copy");
        }
    }

    ThrowingCopy(ThrowingCopy&&) noexcept = default;
    ~ThrowingCopy() = default;
    ThrowingCopy& operator=(const ThrowingCopy&) = delete;
    ThrowingCopy& operator=(ThrowingCopy&&) = delete;
};

static_assert(std::is_copy_constructible<Optional<int>>::value, "copyable Optional must be copy constructible");
static_assert(std::is_copy_assignable<Optional<int>>::value, "copyable Optional must be copy assignable");
static_assert(!std::is_copy_constructible<Optional<std::unique_ptr<int>>>::value, "move-only Optional must not be copy constructible");
static_assert(!std::is_copy_assignable<Optional<std::unique_ptr<int>>>::value, "move-only Optional must not be copy assignable");
static_assert(std::is_copy_assignable<Optional<CopyConstructibleNotAssignable>>::value, "Optional assignment reconstructs its value");
static_assert(std::is_same<decltype(std::declval<Optional<int>&&>().Value()), int>::value, "rvalue Optional access returns by value");
static_assert(!noexcept(std::declval<Optional<int>&&>().Value()), "checked rvalue Optional access may throw");
static_assert(noexcept(std::declval<const Optional<int>&>().ValueOr(std::declval<const int&>())), "nonthrowing scalar ValueOr remains nonthrowing");
static_assert(std::is_nothrow_move_constructible<Optional<int>>::value, "Optional<int> move construction is nonthrowing");
static_assert(std::is_nothrow_move_assignable<Optional<int>>::value, "Optional<int> move assignment is nonthrowing");
static_assert(!std::is_nothrow_copy_constructible<ThrowingCopy>::value, "test isolates a throwing copy");
static_assert(std::is_nothrow_move_constructible<ThrowingCopy>::value, "test copy type has a nonthrowing move");
static_assert(!noexcept(std::declval<const Optional<ThrowingCopy>&>().ValueOr(std::declval<ThrowingCopy>())),
    "const ValueOr must permit a throwing copy");
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

TEST_F(OptionalTest, ValueOrPropagatesThrowingCopyAndIsolatesFallbackMove)
{
    // Engaged: the stored value's copy (for the by-value return) is what
    // can throw, not the fallback construction.
    ThrowingCopyState state;
    const Optional<ThrowingCopy> present(ThrowingCopy(state, 7));
    state.copies = 0;
    state.armed = true;
    EXPECT_THROW(present.ValueOr(ThrowingCopy(state, 42)), std::runtime_error);
    EXPECT_EQ(1, state.copies);

    // Empty: a prvalue fallback is move-constructed into the parameter and
    // moved back out on return, so the throwing copy never runs.
    state.armed = false;
    const Optional<ThrowingCopy> empty{};
    state.copies = 0;
    state.armed = true;
    EXPECT_EQ(42, empty.ValueOr(ThrowingCopy(state, 42)).value);
    EXPECT_EQ(0, state.copies);
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

TEST_F(OptionalTest, EmptyArrowOperatorThrows)
{
    Optional<std::string> empty;
    const Optional<std::string>& constEmpty = empty;
    EXPECT_THROW(empty.operator->(), std::logic_error);
    EXPECT_THROW(constEmpty.operator->(), std::logic_error);
}

TEST_F(OptionalTest, MovedFromArrowOperatorThrowsAndStaysEmpty)
{
    Optional<std::string> source("foo");
    Optional<std::string> destination(std::move(source));
    ASSERT_FALSE(source.HasValue());
    const Optional<std::string>& constSource = source;
    EXPECT_THROW(source.operator->(), std::logic_error);
    EXPECT_THROW(constSource.operator->(), std::logic_error);
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
