// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Result.h"

#include "MmiResults.h"

#include <cerrno>
#include <gtest/gtest.h>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>

using Kompli::AuditResult;
using Kompli::Error;
using Kompli::Result;
using Kompli::Status;

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

static_assert(std::is_copy_constructible<Result<int>>::value, "copyable Result must be copy constructible");
static_assert(std::is_copy_assignable<Result<int>>::value, "copyable Result must be copy assignable");
static_assert(!std::is_copy_constructible<Result<std::unique_ptr<int>>>::value, "move-only Result must not be copy constructible");
static_assert(!std::is_copy_assignable<Result<std::unique_ptr<int>>>::value, "move-only Result must not be copy assignable");
static_assert(std::is_copy_assignable<Result<CopyConstructibleNotAssignable>>::value, "Result assignment reconstructs its value");
static_assert(std::is_same<decltype(std::declval<Result<int>&&>().Value()), int>::value, "rvalue Result access returns by value");
static_assert(noexcept(std::declval<const Result<int>&>().ValueOr(std::declval<const int&>())), "nonthrowing scalar ValueOr remains nonthrowing");
static_assert(std::is_nothrow_move_constructible<Result<int>>::value, "Result<int> move construction is nonthrowing");
static_assert(std::is_nothrow_move_assignable<Result<int>>::value, "Result<int> move assignment is nonthrowing");
static_assert(!std::is_nothrow_copy_constructible<ThrowingCopy>::value, "test isolates a throwing copy");
static_assert(std::is_nothrow_move_constructible<ThrowingCopy>::value, "test copy type has a nonthrowing move");
static_assert(!noexcept(std::declval<const Result<ThrowingCopy>&>().ValueOr(std::declval<ThrowingCopy>())),
    "const ValueOr must permit a throwing copy");
static_assert(noexcept(std::declval<Result<ThrowingCopy>&&>().ValueOr(std::declval<ThrowingCopy>())), "rvalue ValueOr cannot throw a fallback move");
} // namespace

class ResultTest : public ::testing::Test
{
};

namespace
{
// Reproduces the ComplianceEngineInterface.cpp "audit error -> NonCompliant
// AuditResult" reassignment idiom (below) in a single translation unit: the
// real producer, Engine::MmiGet, lives in a separate TU (Engine.cpp) from its
// ComplianceEngineInterface.cpp caller, but putting a stand-in producer here,
// next to the caller shape, lets GCC Release (-O3) inline it -- exactly the
// shape that exposed the stale-alias read below. A cross-TU call (no LTO)
// does not reproduce it.
Result<AuditResult> DispatchRuleNotFound()
{
    return Error("Rule not found", EINVAL);
}
} // namespace

// Characterizes the ComplianceEngineInterface.cpp
// "audit error -> NonCompliant AuditResult" reassignment idiom:
//   auto result = engine.MmiGet(objectName);
//   if (!result.HasValue())
//   {
//       result = ComplianceEngine::AuditResult(Status::NonCompliant, "..." + result.Error().message);
//   }
// Before the Result<T> fix, GCC Release (-O3) could inline DispatchRuleNotFound
// into this test body and miscompile the Error -> Value move-assignment so
// that result.Value().status read back as garbage bytes instead of the
// just-constructed Status::NonCompliant, while the payload string was
// correct -- i.e. a security-relevant false PASS. Debug and Clang
// configurations did not reproduce it.
TEST_F(ResultTest, ErrorToValueReassignmentPreservesStatusAndPayload)
{
    auto result = DispatchRuleNotFound();
    ASSERT_FALSE(result.HasValue());

    result = AuditResult(Status::NonCompliant, "Audit failed with a non-critical error: " + result.Error().message);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value().status);
    EXPECT_EQ("Audit failed with a non-critical error: Rule not found", result.Value().payload);
}

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

TEST_F(ResultTest, ConstValueOrPropagatesThrowingCopyAndIsolatesFallbackMove)
{
    // Present value: the stored value's copy (for the by-value return) is
    // what can throw, not the fallback construction.
    ThrowingCopyState state;
    const Result<ThrowingCopy> present(ThrowingCopy(state, 7));
    state.copies = 0;
    state.armed = true;
    EXPECT_THROW(present.ValueOr(ThrowingCopy(state, 42)), std::runtime_error);
    EXPECT_EQ(1, state.copies);

    // Error: a prvalue fallback is move-constructed into the parameter and
    // moved back out on return, so the throwing copy never runs.
    state.armed = false;
    const Result<ThrowingCopy> error(Error("error"));
    state.copies = 0;
    state.armed = true;
    EXPECT_EQ(42, error.ValueOr(ThrowingCopy(state, 42)).value);
    EXPECT_EQ(0, state.copies);
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
    ASSERT_TRUE(moved.HasValue());
    EXPECT_EQ(*moved.Value(), 42);

    Result<std::unique_ptr<int>> destination(Error("old error"));
    destination = std::move(moved);
    ASSERT_TRUE(destination.HasValue());
    EXPECT_EQ(*destination.Value(), 42);
    Result<std::unique_ptr<int>> error(Error("new error"));
    destination = std::move(error);
    ASSERT_FALSE(destination.HasValue());
    EXPECT_EQ(destination.Error().message, "new error");
}

TEST_F(ResultTest, AssigningToMovedFromSourceReinitializesIt)
{
    Result<int> source(42);
    Result<int> moved(std::move(source));

    source = 99;
    ASSERT_TRUE(source.HasValue());
    EXPECT_EQ(99, source.Value());

    Result<int> another(42);
    Result<int> movedAgain(std::move(another));

    another = Error("reinitialized");
    ASSERT_FALSE(another.HasValue());
    EXPECT_EQ("reinitialized", another.Error().message);
}
