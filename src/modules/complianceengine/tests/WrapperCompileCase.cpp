// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "../src/lib/Optional.h"
#include "../src/lib/Result.h"

#include <memory>
#include <type_traits>
#include <utility>

#ifndef WRAPPER_COMPILE_CASE
#error Select a wrapper compile case
#endif

using ComplianceEngine::Error;
using ComplianceEngine::Optional;
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

#if WRAPPER_COMPILE_CASE == 0
static_assert(std::is_copy_constructible<Optional<int>>::value && std::is_copy_assignable<Optional<int>>::value, "Optional int copies");
static_assert(std::is_copy_constructible<Result<int>>::value && std::is_copy_assignable<Result<int>>::value, "Result int copies");
static_assert(!std::is_copy_constructible<Optional<std::unique_ptr<int>>>::value && !std::is_copy_assignable<Optional<std::unique_ptr<int>>>::value,
    "Optional move-only traits");
static_assert(!std::is_copy_constructible<Result<std::unique_ptr<int>>>::value && !std::is_copy_assignable<Result<std::unique_ptr<int>>>::value,
    "Result move-only traits");
static_assert(std::is_copy_assignable<Optional<ConstructibleNotAssignable>>::value && std::is_copy_assignable<Result<ConstructibleNotAssignable>>::value,
    "copy construction suffices for assignment");
static_assert(std::is_same<decltype(std::declval<Optional<int>&&>().Value()), int>::value, "Optional rvalue Value returns by value");
static_assert(std::is_same<decltype(std::declval<Result<int>&&>().Value()), int>::value, "Result rvalue Value returns by value");
static_assert(!noexcept(std::declval<Optional<int>&&>().Value()), "Optional checked access can throw");

void ValidControl()
{
    Optional<int> optional = 1;
    Optional<int> optionalCopy(optional);
    optionalCopy = optional;
    Result<int> result = 1;
    Result<int> resultCopy(result);
    resultCopy = result;

    Optional<std::unique_ptr<int>> moveOnlyOptional(std::unique_ptr<int>(new int(1)));
    Optional<std::unique_ptr<int>> movedOptional(std::move(moveOnlyOptional));
    moveOnlyOptional = std::move(movedOptional);
    Result<std::unique_ptr<int>> moveOnlyResult(std::unique_ptr<int>(new int(1)));
    Result<std::unique_ptr<int>> movedResult(std::move(moveOnlyResult));
    moveOnlyResult = std::move(movedResult);

    Optional<ConstructibleNotAssignable> nonassignableOptional(ConstructibleNotAssignable(1));
    Optional<ConstructibleNotAssignable> otherOptional(nonassignableOptional);
    otherOptional = nonassignableOptional;
    Result<ConstructibleNotAssignable> nonassignableResult(ConstructibleNotAssignable(1));
    Result<ConstructibleNotAssignable> otherResult(nonassignableResult);
    otherResult = nonassignableResult;

    Optional<const int> constOptional(1);
    Result<const int> constResult(1);
    Optional<ThrowingMove> throwingOptional(ThrowingMove(1));
    Result<ThrowingMove> throwingResult(ThrowingMove(1));
    Optional<ThrowingMove> movedThrowingOptional(std::move(throwingOptional));
    Result<ThrowingMove> movedThrowingResult(std::move(throwingResult));
    (void)constOptional;
    (void)constResult;
    (void)movedThrowingOptional;
    (void)movedThrowingResult;
}
#elif WRAPPER_COMPILE_CASE == 1
void CopyMoveOnlyOptional()
{
    Optional<std::unique_ptr<int>> source;
    Optional<std::unique_ptr<int>> copy(source);
}
#elif WRAPPER_COMPILE_CASE == 2
void AssignMoveOnlyOptional()
{
    Optional<std::unique_ptr<int>> source, destination;
    destination = source;
}
#elif WRAPPER_COMPILE_CASE == 3
void CopyMoveOnlyResult()
{
    Result<std::unique_ptr<int>> source(Error("error"));
    Result<std::unique_ptr<int>> copy(source);
}
#elif WRAPPER_COMPILE_CASE == 4
void AssignMoveOnlyResult()
{
    Result<std::unique_ptr<int>> source(Error("error")), destination(Error("old"));
    destination = source;
}
#elif WRAPPER_COMPILE_CASE == 5
void MutateConstOptional()
{
    const Optional<int> value(1);
    value.Value() = 2;
}
#elif WRAPPER_COMPILE_CASE == 6
void MutateConstResult()
{
    const Result<int> value(1);
    value.Value() = 2;
}
#elif WRAPPER_COMPILE_CASE == 7
static_assert(sizeof(Optional<void>) > 0, "instantiate Optional void");
#elif WRAPPER_COMPILE_CASE == 8
static_assert(sizeof(Optional<int&>) > 0, "instantiate Optional reference");
#elif WRAPPER_COMPILE_CASE == 9
static_assert(sizeof(Result<void>) > 0, "instantiate Result void");
#elif WRAPPER_COMPILE_CASE == 10
static_assert(sizeof(Result<int&>) > 0, "instantiate Result reference");
#elif WRAPPER_COMPILE_CASE == 11
static_assert(sizeof(Result<Error>) > 0, "instantiate ambiguous Result Error");
#else
#error Unknown wrapper compile case
#endif
