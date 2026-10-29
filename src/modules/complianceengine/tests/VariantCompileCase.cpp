// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "../src/lib/Variant.h"

#include <type_traits>
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

struct Base
{
};

struct Derived : Base
{
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
    int referent = 3;
    const int constReferent = 4;
    Variant<int&, const int&> mutableRef(InPlaceType<int&>{}, referent);
    Variant<int&, const int&> constRef(InPlaceType<const int&>{}, constReferent);
    (void)mutableRef.Is<int&>();
    (void)constRef.Is<const int&>();
    (void)mutableRef.Get<int&>();
    (void)As<int&>(std::move(static_cast<const Variant<int&, const int&>&>(mutableRef)));
    (void)constRef.Get<const int&>();
    (void)As<const int&>(std::move(constRef));
}
#elif VARIANT_COMPILE_CASE == 1
static_assert(sizeof(Variant<>) > 0, "instantiate empty list");
#elif VARIANT_COMPILE_CASE == 2
static_assert(sizeof(Variant<int, const int>) > 0, "instantiate duplicate list");
#elif VARIANT_COMPILE_CASE == 3
static_assert(sizeof(Variant<int&&>) > 0, "instantiate rvalue reference alternative");
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
#elif VARIANT_COMPILE_CASE == 12
static_assert(std::is_constructible<Variant<const int&>, InPlaceType<const int&>, int&&>::value, "Variant rejects temporary reference binding");
#elif VARIANT_COMPILE_CASE == 13
static_assert(std::is_constructible<Variant<const int&>, InPlaceType<const int&>, const int&&>::value,
    "Variant rejects const rvalue reference binding");
#elif VARIANT_COMPILE_CASE == 14
static_assert(std::is_constructible<Variant<int&>, InPlaceType<int&>, const int&>::value, "Variant rejects const to mutable reference binding");
#elif VARIANT_COMPILE_CASE == 15
static_assert(std::is_constructible<Variant<const int&>, InPlaceType<const int&>, short&>::value, "Variant rejects numeric reference conversion");
#elif VARIANT_COMPILE_CASE == 16
static_assert(std::is_constructible<Variant<const Base&>, InPlaceType<const Base&>, Derived&>::value, "Variant rejects derived reference conversion");
#elif VARIANT_COMPILE_CASE == 17
void UnlistedGet()
{
    Variant<int&, char> value(InPlaceType<char>{}, 'x');
    (void)value.Get<long&>();
}
#elif VARIANT_COMPILE_CASE == 18
void CvMismatchedGet()
{
    int referent = 1;
    Variant<int&, char> value(InPlaceType<int&>{}, referent);
    (void)value.Get<const int&>();
}
#elif VARIANT_COMPILE_CASE == 19
void UnlistedReferenceIs()
{
    Variant<int, char> value(InPlaceType<int>{}, 1);
    (void)value.Is<int&>();
}
#elif VARIANT_COMPILE_CASE == 20
void UnlistedReferenceAs()
{
    Variant<int, char> value(InPlaceType<int>{}, 1);
    (void)As<int&>(value);
}
#elif VARIANT_COMPILE_CASE == 21
void CvMismatchedReferenceIs()
{
    int referent = 1;
    Variant<int&, char> value(InPlaceType<int&>{}, referent);
    (void)value.Is<const int&>();
}
#elif VARIANT_COMPILE_CASE == 22
void CvMismatchedReferenceAs()
{
    int referent = 1;
    Variant<int&, char> value(InPlaceType<int&>{}, referent);
    (void)As<const int&>(value);
}
#elif VARIANT_COMPILE_CASE == 23
void UnlistedValueGet()
{
    Variant<int, char> value(InPlaceType<int>{}, 1);
    (void)value.Get<long>();
}
#elif VARIANT_COMPILE_CASE == 24
void CvMismatchedValueGet()
{
    Variant<int, char> value(InPlaceType<int>{}, 1);
    (void)value.Get<const int>();
}
#else
#error Unknown Variant compile case
#endif
