// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "../src/lib/Result.h"

#include <memory>
#include <type_traits>
#include <utility>

#ifndef RESULT_COMPILE_CASE
#error Select a Result compile case
#endif

using ComplianceEngine::Error;
using ComplianceEngine::Result;

struct ConstructibleNotAssignable
{
    ConstructibleNotAssignable(int);
    ConstructibleNotAssignable(const ConstructibleNotAssignable&) = default;
    ConstructibleNotAssignable(ConstructibleNotAssignable&&) = default;
    ConstructibleNotAssignable& operator=(const ConstructibleNotAssignable&) = delete;
    ConstructibleNotAssignable& operator=(ConstructibleNotAssignable&&) = delete;
};

struct ThrowingMove
{
    ThrowingMove(int);
    ThrowingMove(const ThrowingMove&) = default;
    ThrowingMove(ThrowingMove&&) noexcept(false);
};

#if RESULT_COMPILE_CASE == 0
static_assert(std::is_copy_constructible<Result<int>>::value && std::is_copy_assignable<Result<int>>::value, "Result int copies");
static_assert(!std::is_copy_constructible<Result<std::unique_ptr<int>>>::value && !std::is_copy_assignable<Result<std::unique_ptr<int>>>::value,
    "Result move-only traits");
static_assert(std::is_copy_assignable<Result<ConstructibleNotAssignable>>::value, "copy construction suffices for assignment");
static_assert(std::is_same<decltype(std::declval<Result<int>&&>().Value()), int>::value, "Result rvalue Value returns by value");

void ValidControl()
{
    Result<int> result = 1;
    Result<int> resultCopy(result);
    resultCopy = result;

    Result<std::unique_ptr<int>> moveOnlyResult(std::unique_ptr<int>(new int(1)));
    Result<std::unique_ptr<int>> movedResult(std::move(moveOnlyResult));
    moveOnlyResult = std::move(movedResult);

    Result<ConstructibleNotAssignable> nonassignableResult(ConstructibleNotAssignable(1));
    Result<ConstructibleNotAssignable> otherResult(nonassignableResult);
    otherResult = nonassignableResult;

    Result<const int> constResult(1);
    Result<ThrowingMove> throwingResult(ThrowingMove(1));
    Result<ThrowingMove> movedThrowingResult(std::move(throwingResult));
    (void)constResult;
    (void)movedThrowingResult;
}
#elif RESULT_COMPILE_CASE == 1
void CopyMoveOnlyResult()
{
    Result<std::unique_ptr<int>> source(Error("error"));
    Result<std::unique_ptr<int>> copy(source);
}
#elif RESULT_COMPILE_CASE == 2
void AssignMoveOnlyResult()
{
    Result<std::unique_ptr<int>> source(Error("error")), destination(Error("old"));
    destination = source;
}
#elif RESULT_COMPILE_CASE == 3
void MutateConstResult()
{
    const Result<int> value(1);
    value.Value() = 2;
}
#elif RESULT_COMPILE_CASE == 4
static_assert(sizeof(Result<void>) > 0, "instantiate Result void");
#elif RESULT_COMPILE_CASE == 5
static_assert(sizeof(Result<int&>) > 0, "instantiate Result reference");
#elif RESULT_COMPILE_CASE == 6
static_assert(sizeof(Result<Error>) > 0, "instantiate ambiguous Result Error");
#else
#error Unknown Result compile case
#endif
