// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Positive control: ordinary Result<T> usage below must COMPILE cleanly, so
// the negative Result<T> cases in the sibling files are known to fail for
// their own specific reason rather than a broken translation unit.

#include "../../Result.h"

#include <memory>
#include <type_traits>
#include <utility>

using Kompli::Result;

struct ConstructibleNotAssignable
{
    ConstructibleNotAssignable(int);
    ConstructibleNotAssignable(const ConstructibleNotAssignable&) = default;
    ConstructibleNotAssignable(ConstructibleNotAssignable&&) = default;
    ConstructibleNotAssignable& operator=(const ConstructibleNotAssignable&) = delete;
    ConstructibleNotAssignable& operator=(ConstructibleNotAssignable&&) = delete;
};

static_assert(std::is_copy_constructible<Result<int>>::value && std::is_copy_assignable<Result<int>>::value, "Result int copies");
static_assert(!std::is_copy_constructible<Result<std::unique_ptr<int>>>::value && !std::is_copy_assignable<Result<std::unique_ptr<int>>>::value,
    "Result move-only traits");
static_assert(std::is_copy_assignable<Result<ConstructibleNotAssignable>>::value, "copy construction suffices for assignment");
static_assert(std::is_same<decltype(std::declval<Result<int>&&>().Value()), int>::value, "Result rvalue Value returns by value");
static_assert(!std::is_convertible<Result<int>, bool>::value, "Result bool conversion is explicit");

void ValidControl()
{
    Result<int> result = 5;
    Result<int> resultCopy(result);
    resultCopy = result;
    const int extracted = std::move(resultCopy).Value();
    (void)extracted;

    Result<std::unique_ptr<int>> moveOnlyResult(std::unique_ptr<int>(new int(1)));
    Result<std::unique_ptr<int>> movedResult(std::move(moveOnlyResult));
    moveOnlyResult = std::move(movedResult);

    Result<ConstructibleNotAssignable> nonassignableResult(ConstructibleNotAssignable(1));
    Result<ConstructibleNotAssignable> otherResult(nonassignableResult);
    otherResult = nonassignableResult;

    Result<const int> constResult(1);
    (void)constResult;
}
