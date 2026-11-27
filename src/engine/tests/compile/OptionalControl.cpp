// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Positive control: supported Optional<T> usage below must COMPILE cleanly, so
// the negative Optional<T> cases in the sibling files are known to fail for
// their own specific reason rather than a broken translation unit.

#include "../../Optional.h"

#include <memory>
#include <type_traits>
#include <utility>

using Kompli::Optional;

struct ConstructibleNotAssignable
{
    ConstructibleNotAssignable(int);
    ConstructibleNotAssignable(const ConstructibleNotAssignable&) noexcept(false);
    ConstructibleNotAssignable(ConstructibleNotAssignable&&) noexcept = default;
    ConstructibleNotAssignable& operator=(const ConstructibleNotAssignable&) = delete;
    ConstructibleNotAssignable& operator=(ConstructibleNotAssignable&&) = delete;
};

static_assert(std::is_copy_constructible<Optional<int>>::value && std::is_copy_assignable<Optional<int>>::value, "Optional int copies");
static_assert(!std::is_copy_constructible<Optional<std::unique_ptr<int>>>::value && !std::is_copy_assignable<Optional<std::unique_ptr<int>>>::value,
    "Optional move-only traits");
static_assert(std::is_copy_assignable<Optional<ConstructibleNotAssignable>>::value, "copy construction suffices for assignment");
static_assert(std::is_same<decltype(std::declval<Optional<int>&&>().Value()), int>::value, "Optional rvalue Value returns by value");
static_assert(!noexcept(std::declval<Optional<int>&&>().Value()), "Optional checked access can throw");
static_assert(!std::is_convertible<Optional<int>, bool>::value, "Optional bool conversion must be explicit");
static_assert(!std::is_convertible<Optional<int>, int>::value, "Optional must not convert implicitly to integers");
static_assert(noexcept(std::declval<const Optional<int>&>().HasValue()), "Optional engagement query must be noexcept");
static_assert(noexcept(static_cast<bool>(std::declval<const Optional<int>&>())), "Optional explicit bool conversion must be noexcept");
static_assert(noexcept(Optional<ConstructibleNotAssignable>(std::declval<ConstructibleNotAssignable&&>())),
    "Optional construction from a nothrow-movable rvalue must be noexcept");
static_assert(!noexcept(Optional<ConstructibleNotAssignable>(std::declval<const ConstructibleNotAssignable&>())),
    "Optional construction from an lvalue must reflect argument copying");

void ValidControl()
{
    Optional<int> optional = 1;
    (void)!optional;
    (void)(optional && true);
    if (optional)
    {
        (void)static_cast<bool>(optional);
    }

    Optional<int> optionalCopy(optional);
    optionalCopy = optional;
    const int extracted = std::move(optionalCopy).Value();
    (void)extracted;

    Optional<std::unique_ptr<int>> moveOnlyOptional(std::unique_ptr<int>(new int(1)));
    Optional<std::unique_ptr<int>> movedOptional(std::move(moveOnlyOptional));
    moveOnlyOptional = std::move(movedOptional);

    Optional<ConstructibleNotAssignable> nonassignableOptional(ConstructibleNotAssignable(1));
    Optional<ConstructibleNotAssignable> otherOptional(nonassignableOptional);
    otherOptional = nonassignableOptional;

    Optional<const int> constOptional(1);
    (void)constOptional;
}
