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

template <typename...>
struct MakeVoid
{
    using Type = void;
};

template <typename T, typename = void>
struct HasValueAccessor : std::false_type
{
};

template <typename T>
struct HasValueAccessor<T, typename MakeVoid<decltype(std::declval<T&>().Value())>::Type> : std::true_type
{
};

template <typename T, typename = void>
struct HasValueOrAccessor : std::false_type
{
};

template <typename T>
struct HasValueOrAccessor<T, typename MakeVoid<decltype(std::declval<T&>().ValueOr(0))>::Type> : std::true_type
{
};

static_assert(!std::is_default_constructible<Result<void>>::value, "void success requires Success()");
static_assert(!HasValueAccessor<Result<void>>::value, "void Result has no Value()");
static_assert(!HasValueOrAccessor<Result<void>>::value, "void Result has no ValueOr()");
static_assert(std::is_convertible<Error, Result<void>>::value, "Error implicitly constructs void Result");
static_assert(!std::is_convertible<int, Error>::value, "integer cannot implicitly construct Error");
static_assert(!std::is_convertible<int, Result<void>>::value, "integer cannot implicitly construct void Result");
static_assert(std::is_convertible<int, Result<int>>::value, "integer remains a Result<int> value");
static_assert(std::is_nothrow_constructible<Error, int>::value, "code-only Error construction is nonthrowing");
static_assert(std::is_nothrow_constructible<Result<void>, Error&&>::value, "rvalue Error construction is nonthrowing");
static_assert(!std::is_nothrow_constructible<Result<void>, const Error&>::value, "lvalue Error copying may throw");
static_assert(std::is_nothrow_move_constructible<Result<void>>::value, "void Result move construction is nonthrowing");
static_assert(std::is_nothrow_move_assignable<Result<void>>::value, "void Result move assignment is nonthrowing");
static_assert(noexcept(Result<void>::Success()), "void Result success factory is nonthrowing");
static_assert(std::is_copy_constructible<Result<void>>::value && std::is_copy_assignable<Result<void>>::value, "void Result copies");
static_assert(std::is_move_constructible<Result<void>>::value && std::is_move_assignable<Result<void>>::value, "void Result moves");
static_assert(std::is_same<decltype(std::declval<const Result<void>&>().Error()), const Error&>::value,
    "const void Result returns a const error reference");
static_assert(std::is_same<decltype(std::declval<Result<void>&>().Error()), Error&>::value, "mutable void Result returns a mutable error reference");
static_assert(std::is_same<decltype(std::declval<Result<void>&&>().Error()), Error>::value, "rvalue void Result returns an error by value");
static_assert(!std::is_convertible<Result<void>, bool>::value, "void Result has explicit bool conversion");
static_assert(std::is_constructible<bool, Result<void>>::value, "void Result supports contextual bool conversion");

Result<void> ForwardVoidFailure(Result<void> result)
{
    if (!result)
    {
        return std::move(result).Error();
    }
    return Result<void>::Success();
}

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

TEST_F(ResultTest, MovedFromValueSourceThrowsOnAccessAndReturnsFallback)
{
    Result<int> source(42);
    Result<int> destination(std::move(source));
    ASSERT_FALSE(source.HasValue());
    const Result<int>& constSource = source;

    EXPECT_THROW(source.Value(), std::logic_error);
    EXPECT_THROW(constSource.Value(), std::logic_error);
    EXPECT_THROW(std::move(source).Value(), std::logic_error);
    EXPECT_THROW(source.Error(), std::logic_error);
    EXPECT_THROW(constSource.Error(), std::logic_error);
    EXPECT_THROW(std::move(source).Error(), std::logic_error);
    EXPECT_THROW(source.operator->(), std::logic_error);
    EXPECT_THROW(constSource.operator->(), std::logic_error);

    EXPECT_EQ(7, source.ValueOr(7));
    EXPECT_EQ(7, std::move(source).ValueOr(7));
}

TEST_F(ResultTest, MovedFromErrorSourceThrowsOnAccessAndReturnsFallback)
{
    Result<int> source(Error("boom"));
    Result<int> destination(std::move(source));
    ASSERT_FALSE(source.HasValue());
    const Result<int>& constSource = source;

    EXPECT_THROW(source.Value(), std::logic_error);
    EXPECT_THROW(constSource.Value(), std::logic_error);
    EXPECT_THROW(std::move(source).Value(), std::logic_error);
    EXPECT_THROW(source.Error(), std::logic_error);
    EXPECT_THROW(constSource.Error(), std::logic_error);
    EXPECT_THROW(std::move(source).Error(), std::logic_error);
    EXPECT_THROW(source.operator->(), std::logic_error);
    EXPECT_THROW(constSource.operator->(), std::logic_error);

    EXPECT_EQ(7, source.ValueOr(7));
    EXPECT_EQ(7, std::move(source).ValueOr(7));
}

TEST_F(ResultTest, CopyingOrMovingMovedFromSourceGivesMovedFromDestination)
{
    Result<int> source(42);
    Result<int> firstMove(std::move(source));
    ASSERT_FALSE(source.HasValue());

    Result<int> copyOfMovedFrom(source);
    EXPECT_FALSE(copyOfMovedFrom.HasValue());
    EXPECT_THROW(copyOfMovedFrom.Value(), std::logic_error);
    EXPECT_THROW(copyOfMovedFrom.Error(), std::logic_error);

    Result<int> moveOfMovedFrom(std::move(source));
    EXPECT_FALSE(moveOfMovedFrom.HasValue());
    EXPECT_THROW(moveOfMovedFrom.Value(), std::logic_error);
    EXPECT_THROW(moveOfMovedFrom.Error(), std::logic_error);
}

TEST_F(ResultTest, AssigningToMovedFromSourceReinitializesIt)
{
    Result<int> source(42);
    Result<int> moved(std::move(source));
    ASSERT_FALSE(source.HasValue());

    source = 99;
    ASSERT_TRUE(source.HasValue());
    EXPECT_EQ(99, source.Value());

    Result<int> another(42);
    Result<int> movedAgain(std::move(another));
    ASSERT_FALSE(another.HasValue());

    another = Error("reinitialized");
    ASSERT_FALSE(another.HasValue());
    EXPECT_EQ("reinitialized", another.Error().message);
}

TEST_F(ResultTest, MovedFromValueSourceAssignmentPropagatesMovedFromState)
{
    Result<int> source(42);
    Result<int> moved(std::move(source));
    ASSERT_FALSE(source.HasValue());

    Result<int> copyDestinationValue(7);
    copyDestinationValue = source;
    EXPECT_FALSE(copyDestinationValue.HasValue());
    EXPECT_THROW(copyDestinationValue.Value(), std::logic_error);
    EXPECT_THROW(copyDestinationValue.Error(), std::logic_error);

    Result<int> copyDestinationError(Error("existing"));
    copyDestinationError = source;
    EXPECT_FALSE(copyDestinationError.HasValue());
    EXPECT_THROW(copyDestinationError.Value(), std::logic_error);
    EXPECT_THROW(copyDestinationError.Error(), std::logic_error);

    Result<int> moveDestination(7);
    moveDestination = std::move(source);
    EXPECT_FALSE(moveDestination.HasValue());
    EXPECT_THROW(moveDestination.Value(), std::logic_error);
    EXPECT_THROW(moveDestination.Error(), std::logic_error);

    EXPECT_FALSE(source.HasValue());
    EXPECT_THROW(source.Error(), std::logic_error);
}

TEST_F(ResultTest, MovedFromErrorSourceAssignmentPropagatesMovedFromState)
{
    Result<int> source(Error("boom"));
    Result<int> moved(std::move(source));
    ASSERT_FALSE(source.HasValue());

    Result<int> copyDestinationValue(7);
    copyDestinationValue = source;
    EXPECT_FALSE(copyDestinationValue.HasValue());
    EXPECT_THROW(copyDestinationValue.Value(), std::logic_error);
    EXPECT_THROW(copyDestinationValue.Error(), std::logic_error);

    Result<int> copyDestinationError(Error("existing"));
    copyDestinationError = source;
    EXPECT_FALSE(copyDestinationError.HasValue());
    EXPECT_THROW(copyDestinationError.Value(), std::logic_error);
    EXPECT_THROW(copyDestinationError.Error(), std::logic_error);

    Result<int> moveDestination(7);
    moveDestination = std::move(source);
    EXPECT_FALSE(moveDestination.HasValue());
    EXPECT_THROW(moveDestination.Value(), std::logic_error);
    EXPECT_THROW(moveDestination.Error(), std::logic_error);

    EXPECT_FALSE(source.HasValue());
    EXPECT_THROW(source.Error(), std::logic_error);
}

TEST_F(ResultTest, CodeOnlyErrorRetainsEmptyMessageAndIntIsValue)
{
    Error error(2);
    EXPECT_EQ(2, error.code);
    EXPECT_TRUE(error.message.empty());
    Result<void> failure = error;
    EXPECT_FALSE(failure.HasValue());
    EXPECT_EQ(2, failure.Error().code);
    EXPECT_TRUE(failure.Error().message.empty());
    Result<int> value = 5;
    ASSERT_TRUE(value.HasValue());
    EXPECT_EQ(5, value.Value());
}

TEST_F(ResultTest, VoidSuccessRequiresFactory)
{
    Result<void> result = Result<void>::Success();
    EXPECT_TRUE(result.HasValue());
    EXPECT_TRUE(static_cast<bool>(result));
    EXPECT_THROW(result.Error(), std::logic_error);
    EXPECT_THROW(static_cast<const Result<void>&>(result).Error(), std::logic_error);
    EXPECT_THROW(std::move(result).Error(), std::logic_error);
}

TEST_F(ResultTest, VoidErrorPreservesPayloadAndAccessQualifiers)
{
    Result<void> result = Error("failure", 42);
    EXPECT_FALSE(result.HasValue());
    EXPECT_FALSE(static_cast<bool>(result));
    const Result<void>& constResult = result;
    EXPECT_EQ(&result.Error(), &constResult.Error());
    EXPECT_EQ(42, constResult.Error().code);
    result.Error().message = "updated";
    Error extracted = std::move(result).Error();
    EXPECT_EQ(42, extracted.code);
    EXPECT_EQ("updated", extracted.message);
}

TEST_F(ResultTest, VoidCopyAndMoveConstruction)
{
    Result<void> success = Result<void>::Success();
    Result<void> successCopy(success);
    Result<void> successMove(std::move(success));
    EXPECT_FALSE(success.HasValue());
    EXPECT_THROW(success.Error(), std::logic_error);
    EXPECT_TRUE(successCopy.HasValue());
    EXPECT_TRUE(successMove.HasValue());

    Result<void> failure = Error("source", 17);
    Result<void> failureCopy(failure);
    Result<void> failureMove(std::move(failure));
    EXPECT_FALSE(failure.HasValue());
    EXPECT_THROW(failure.Error(), std::logic_error);
    EXPECT_FALSE(failureCopy.HasValue());
    EXPECT_EQ("source", failureCopy.Error().message);
    EXPECT_FALSE(failureMove.HasValue());
    EXPECT_EQ(17, failureMove.Error().code);
    EXPECT_EQ("source", failureMove.Error().message);
}

TEST_F(ResultTest, VoidCopyAndMoveAssignment)
{
    Result<void> success = Result<void>::Success();
    Result<void> failure = Error("original", 13);
    success = failure;
    EXPECT_FALSE(success.HasValue());
    EXPECT_EQ("original", success.Error().message);
    success = Result<void>::Success();
    EXPECT_TRUE(success.HasValue());
    failure = success;
    EXPECT_TRUE(failure.HasValue());

    failure = Error("next", 29);
    success = std::move(failure);
    EXPECT_FALSE(failure.HasValue());
    EXPECT_THROW(failure.Error(), std::logic_error);
    EXPECT_FALSE(success.HasValue());
    EXPECT_EQ(29, success.Error().code);
    EXPECT_EQ("next", success.Error().message);
    Result<void> replacement = Error("old");
    replacement = std::move(success);
    EXPECT_FALSE(success.HasValue());
    EXPECT_THROW(success.Error(), std::logic_error);
    EXPECT_EQ(29, replacement.Error().code);
    EXPECT_EQ("next", replacement.Error().message);
    success = Result<void>::Success();
    EXPECT_TRUE(success.HasValue());

    Result<void>& alias = success;
    success = alias;
    success = std::move(alias);
    EXPECT_TRUE(success.HasValue());
    success = Error("self", 31);
    success = alias;
    success = std::move(alias);
    EXPECT_FALSE(success.HasValue());
    EXPECT_EQ("self", success.Error().message);
}

TEST_F(ResultTest, VoidSelfMoveOnMovedFromSourceStaysMovedFrom)
{
    Result<void> success = Result<void>::Success();
    Result<void> destination(std::move(success));
    ASSERT_FALSE(success.HasValue());

    Result<void>& alias = success;
    success = std::move(alias);
    EXPECT_FALSE(success.HasValue());
    EXPECT_THROW(success.Error(), std::logic_error);
}

TEST_F(ResultTest, VoidMovedFromSourcePropagatesAndReinitializes)
{
    Result<void> success = Result<void>::Success();
    Result<void> moved(std::move(success));
    ASSERT_FALSE(success.HasValue());
    EXPECT_THROW(success.Error(), std::logic_error);

    Result<void> copyOfMovedFrom(success);
    EXPECT_FALSE(copyOfMovedFrom.HasValue());
    EXPECT_THROW(copyOfMovedFrom.Error(), std::logic_error);

    Result<void> moveOfMovedFrom(std::move(success));
    EXPECT_FALSE(moveOfMovedFrom.HasValue());
    EXPECT_THROW(moveOfMovedFrom.Error(), std::logic_error);

    success = Error("reinitialized", 5);
    EXPECT_FALSE(success.HasValue());
    EXPECT_EQ(5, success.Error().code);

    Result<void> anotherFailure = Error("gone", 9);
    Result<void> anotherMoved(std::move(anotherFailure));
    ASSERT_FALSE(anotherFailure.HasValue());
    anotherFailure = Result<void>::Success();
    EXPECT_TRUE(anotherFailure.HasValue());
}

TEST_F(ResultTest, VoidMovedFromSuccessSourceAssignmentPropagatesMovedFromState)
{
    Result<void> source = Result<void>::Success();
    Result<void> moved(std::move(source));
    ASSERT_FALSE(source.HasValue());

    Result<void> copyDestinationSuccess = Result<void>::Success();
    copyDestinationSuccess = source;
    EXPECT_FALSE(copyDestinationSuccess.HasValue());
    EXPECT_THROW(copyDestinationSuccess.Error(), std::logic_error);

    Result<void> copyDestinationFailure = Error("existing", 11);
    copyDestinationFailure = source;
    EXPECT_FALSE(copyDestinationFailure.HasValue());
    EXPECT_THROW(copyDestinationFailure.Error(), std::logic_error);

    Result<void> moveDestinationSuccess = Result<void>::Success();
    moveDestinationSuccess = std::move(source);
    EXPECT_FALSE(moveDestinationSuccess.HasValue());
    EXPECT_THROW(moveDestinationSuccess.Error(), std::logic_error);

    Result<void> moveDestinationFailure = Error("existing", 12);
    moveDestinationFailure = std::move(source);
    EXPECT_FALSE(moveDestinationFailure.HasValue());
    EXPECT_THROW(moveDestinationFailure.Error(), std::logic_error);

    EXPECT_FALSE(source.HasValue());
    EXPECT_THROW(source.Error(), std::logic_error);
}

TEST_F(ResultTest, VoidMovedFromFailureSourceAssignmentPropagatesMovedFromState)
{
    Result<void> source = Error("boom", 7);
    Result<void> moved(std::move(source));
    ASSERT_FALSE(source.HasValue());

    Result<void> copyDestinationSuccess = Result<void>::Success();
    copyDestinationSuccess = source;
    EXPECT_FALSE(copyDestinationSuccess.HasValue());
    EXPECT_THROW(copyDestinationSuccess.Error(), std::logic_error);

    Result<void> copyDestinationFailure = Error("existing", 11);
    copyDestinationFailure = source;
    EXPECT_FALSE(copyDestinationFailure.HasValue());
    EXPECT_THROW(copyDestinationFailure.Error(), std::logic_error);

    Result<void> moveDestinationSuccess = Result<void>::Success();
    moveDestinationSuccess = std::move(source);
    EXPECT_FALSE(moveDestinationSuccess.HasValue());
    EXPECT_THROW(moveDestinationSuccess.Error(), std::logic_error);

    Result<void> moveDestinationFailure = Error("existing", 12);
    moveDestinationFailure = std::move(source);
    EXPECT_FALSE(moveDestinationFailure.HasValue());
    EXPECT_THROW(moveDestinationFailure.Error(), std::logic_error);

    EXPECT_FALSE(source.HasValue());
    EXPECT_THROW(source.Error(), std::logic_error);
}

TEST_F(ResultTest, VoidCopyAssignmentReplacesStatesAndPreservesSelfAssignment)
{
    Result<void> source = Error("new failure", 29);
    Result<void> destination = Error("old failure", 13);
    destination = source;
    ASSERT_FALSE(destination.HasValue());
    EXPECT_EQ(29, destination.Error().code);
    EXPECT_EQ("new failure", destination.Error().message);
    EXPECT_EQ("new failure", source.Error().message);

    Result<void>& failureAlias = destination;
    destination = failureAlias;
    EXPECT_EQ(29, destination.Error().code);
    EXPECT_EQ("new failure", destination.Error().message);

    Result<void> success = Result<void>::Success();
    destination = success;
    EXPECT_TRUE(destination.HasValue());
    destination = source;
    ASSERT_FALSE(destination.HasValue());
    EXPECT_EQ(29, destination.Error().code);
    EXPECT_EQ("new failure", destination.Error().message);
    success = destination;
    ASSERT_FALSE(success.HasValue());
    EXPECT_EQ(29, success.Error().code);
    EXPECT_EQ("new failure", success.Error().message);
}

TEST_F(ResultTest, VoidFailureForwarding)
{
    Result<void> failure = ForwardVoidFailure(Error("forwarded", 53));
    ASSERT_FALSE(failure.HasValue());
    EXPECT_EQ(53, failure.Error().code);
    EXPECT_EQ("forwarded", failure.Error().message);
    EXPECT_TRUE(ForwardVoidFailure(Result<void>::Success()).HasValue());
}
