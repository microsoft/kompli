// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "../src/lib/Variant.h"

#include <utility>

#ifndef VARIANT_COMPILE_CASE
#error Select a Variant compile case
#endif

using ComplianceEngine::As;
using ComplianceEngine::InPlaceType;
using ComplianceEngine::Variant;

struct ThrowingMove
{
    ThrowingMove(ThrowingMove&&) noexcept(false);
    ThrowingMove& operator=(ThrowingMove&&) noexcept(false);
};

struct NoMoveAssignment
{
    NoMoveAssignment(NoMoveAssignment&&) noexcept = default;
    NoMoveAssignment& operator=(NoMoveAssignment&&) = delete;
};

struct ThrowingDestructor
{
    ThrowingDestructor(ThrowingDestructor&&) noexcept = default;
    ThrowingDestructor& operator=(ThrowingDestructor&&) noexcept = default;
    ~ThrowingDestructor() noexcept(false);
};

#if VARIANT_COMPILE_CASE == 0
void ValidControl()
{
    Variant<int, char> value(InPlaceType<int>{}, 1);
    (void)value.Is<int>();
    (void)value.Get<int>();
    (void)As<int>(value);
    const Variant<int, char>& constView = value;
    (void)As<int>(constView);
    (void)As<int>(std::move(value));
    (void)As<int>(std::move(constView));
}
#elif VARIANT_COMPILE_CASE == 1
static_assert(sizeof(Variant<>) > 0, "instantiate empty list");
#elif VARIANT_COMPILE_CASE == 2
static_assert(sizeof(Variant<int, const int>) > 0, "instantiate duplicate list");
#elif VARIANT_COMPILE_CASE == 3
static_assert(sizeof(Variant<int&>) > 0, "instantiate reference alternative");
#elif VARIANT_COMPILE_CASE == 4
static_assert(sizeof(Variant<void>) > 0, "instantiate void alternative");
#elif VARIANT_COMPILE_CASE == 5
static_assert(sizeof(Variant<ThrowingMove>) > 0, "instantiate throwing move alternative");
#elif VARIANT_COMPILE_CASE == 6
static_assert(sizeof(Variant<NoMoveAssignment>) > 0, "instantiate deleted move assignment");
#elif VARIANT_COMPILE_CASE == 7
static_assert(sizeof(Variant<ThrowingDestructor>) > 0, "instantiate throwing destructor");
#elif VARIANT_COMPILE_CASE == 8
void UnlistedQuery()
{
    Variant<int, char> value(InPlaceType<int>{}, 1);
    (void)value.Is<long>();
}
#elif VARIANT_COMPILE_CASE == 9
void CvMismatchedQuery()
{
    Variant<int, char> value(InPlaceType<int>{}, 1);
    (void)value.Is<const int>();
}
#elif VARIANT_COMPILE_CASE == 10
void UnlistedAs()
{
    Variant<int, char> value(InPlaceType<int>{}, 1);
    (void)As<long>(value);
}
#elif VARIANT_COMPILE_CASE == 11
void CvMismatchedAs()
{
    Variant<int, char> value(InPlaceType<int>{}, 1);
    (void)As<const int>(value);
}
#else
#error Unknown Variant compile case
#endif
