// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "../Optional.h"

#include <memory>
#include <type_traits>
#include <utility>

#ifndef OPTIONAL_COMPILE_CASE
#error Select an Optional compile case
#endif

using ComplianceEngine::Optional;

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

struct ThrowingDestructor
{
    ~ThrowingDestructor() noexcept(false);
};

#if OPTIONAL_COMPILE_CASE == 0
static_assert(std::is_copy_constructible<Optional<int>>::value && std::is_copy_assignable<Optional<int>>::value, "Optional int copies");
static_assert(!std::is_copy_constructible<Optional<std::unique_ptr<int>>>::value && !std::is_copy_assignable<Optional<std::unique_ptr<int>>>::value,
    "Optional move-only traits");
static_assert(std::is_copy_assignable<Optional<ConstructibleNotAssignable>>::value, "copy construction suffices for assignment");
static_assert(std::is_same<decltype(std::declval<Optional<int>&&>().Value()), int>::value, "Optional rvalue Value returns by value");
static_assert(!noexcept(std::declval<Optional<int>&&>().Value()), "Optional checked access can throw");

void ValidControl()
{
    Optional<int> optional = 1;
    Optional<int> optionalCopy(optional);
    optionalCopy = optional;

    Optional<std::unique_ptr<int>> moveOnlyOptional(std::unique_ptr<int>(new int(1)));
    Optional<std::unique_ptr<int>> movedOptional(std::move(moveOnlyOptional));
    moveOnlyOptional = std::move(movedOptional);

    Optional<ConstructibleNotAssignable> nonassignableOptional(ConstructibleNotAssignable(1));
    Optional<ConstructibleNotAssignable> otherOptional(nonassignableOptional);
    otherOptional = nonassignableOptional;

    Optional<const int> constOptional(1);
    (void)constOptional;
}
#elif OPTIONAL_COMPILE_CASE == 1
void CopyMoveOnlyOptional()
{
    Optional<std::unique_ptr<int>> source;
    Optional<std::unique_ptr<int>> copy(source);
}
#elif OPTIONAL_COMPILE_CASE == 2
void AssignMoveOnlyOptional()
{
    Optional<std::unique_ptr<int>> source, destination;
    destination = source;
}
#elif OPTIONAL_COMPILE_CASE == 3
void MutateConstOptional()
{
    const Optional<int> value(1);
    value.Value() = 2;
}
#elif OPTIONAL_COMPILE_CASE == 4
static_assert(sizeof(Optional<void>) > 0, "instantiate Optional void");
#elif OPTIONAL_COMPILE_CASE == 5
static_assert(sizeof(Optional<int&>) > 0, "instantiate Optional reference");
#elif OPTIONAL_COMPILE_CASE == 6
static_assert(sizeof(Optional<ThrowingMove>) > 0, "instantiate Optional with a throwing move");
#elif OPTIONAL_COMPILE_CASE == 7
static_assert(sizeof(Optional<ThrowingDestructor>) > 0, "instantiate Optional with a throwing destructor");
#else
#error Unknown Optional compile case
#endif
