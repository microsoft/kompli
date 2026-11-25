// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Variant.hpp"

#include "TypeTraits.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>

using Kompli::As;
using Kompli::InPlaceType;
using Kompli::MovableVariant;
using Kompli::Variant;
namespace TypeTraits = Kompli::TypeTraits;

namespace
{
static_assert(TypeTraits::All<>::value, "empty boolean pack is true");
static_assert(TypeTraits::All<true, true>::value, "all true");
static_assert(!TypeTraits::All<true, false>::value, "one false rejects the pack");
static_assert(0 == TypeTraits::Count<int>::value, "count in empty type pack");
static_assert(2 == TypeTraits::Count<const int, int, volatile int, char>::value, "count ignores top-level cv");
static_assert(0 == TypeTraits::Count<int, char, short>::value, "count absent type");
static_assert(TypeTraits::Unique<>::value, "empty type pack is unique");
static_assert(TypeTraits::Unique<int, char>::value, "distinct types are unique");
static_assert(!TypeTraits::Unique<int, const int>::value, "uniqueness ignores top-level cv");
static_assert(1 == TypeTraits::Find<int, char, const int, long>::Index, "find matching index");
static_assert(std::is_same<typename TypeTraits::Find<int, char, const int, long>::Type, const int>::value, "find preserves listed cv");
static_assert(0 == TypeTraits::Find<volatile int, int, const int>::Index, "find selects first cv-insensitive match");
static_assert(2 == TypeTraits::Find<int, char, long>::Index, "missing index equals pack length");
static_assert(std::is_same<typename TypeTraits::Find<int, char, long>::Type, void>::value, "missing type is void");
static_assert(0 == TypeTraits::Find<int>::Index, "empty pack has zero index");
static_assert(std::is_same<typename TypeTraits::Find<int>::Type, void>::value, "empty pack has no type");
static_assert(7 == TypeTraits::Max(7), "one size_t value");
static_assert(9 == TypeTraits::Max(std::size_t{2}, std::size_t{9}, std::size_t{4}), "maximum of multiple values");

struct alignas(128) Wide
{
    char data[256] = {};
};

struct Large
{
    char data[513] = {};
};

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
    ~ThrowingDestructor() noexcept(false)
    {
    }
};

struct CountingDeleter
{
    int* deletions;

    void operator()(int* value) const noexcept
    {
        ++*deletions;
        delete value;
    }
};

using OwnedInt = std::unique_ptr<int, CountingDeleter>;
using Scalar = Variant<int, char>;
using Owner = Variant<OwnedInt, char>;

static_assert(std::is_same<Scalar, MovableVariant<int, char>>::value, "Variant selects the move-only profile");
static_assert(!std::is_default_constructible<Scalar>::value, "no default construction");
static_assert(!std::is_copy_constructible<Scalar>::value, "even builtin alternatives do not enable Variant copy");
static_assert(!std::is_copy_assignable<Scalar>::value, "Variant copy assignment is deleted");
static_assert(!std::is_copy_constructible<Owner>::value, "resource owner cannot copy");
static_assert(!std::is_copy_assignable<Owner>::value, "resource owner cannot copy-assign");
static_assert(std::is_nothrow_move_constructible<Scalar>::value, "nonthrowing move construction");
static_assert(std::is_nothrow_move_assignable<Scalar>::value, "nonthrowing move assignment");
static_assert(std::is_nothrow_move_constructible<Owner>::value, "move-only resource owner");
static_assert(std::is_nothrow_move_assignable<Owner>::value, "move-only resource assignment");
static_assert(std::is_nothrow_destructible<Owner>::value, "nonthrowing destruction");
static_assert(!std::is_nothrow_move_constructible<ThrowingMove>::value, "unsupported throwing move");
static_assert(!std::is_nothrow_move_assignable<ThrowingMove>::value, "unsupported throwing assignment");
static_assert(!std::is_nothrow_move_assignable<NoMoveAssignment>::value, "unsupported absent move assignment");
static_assert(!std::is_nothrow_destructible<ThrowingDestructor>::value, "unsupported throwing destruction");
static_assert(std::is_constructible<Scalar, InPlaceType<int>, int>::value, "exact value construction");
static_assert(!std::is_constructible<Scalar, InPlaceType<int>, short>::value, "reject converted value");
static_assert(!std::is_constructible<Scalar, InPlaceType<long>, long>::value, "reject unlisted tag");
static_assert(!std::is_constructible<Scalar, int>::value, "tag required");
static_assert(!std::is_constructible<Scalar, InPlaceType<int>, int, int>::value, "one value only");
static_assert(!std::is_constructible<Owner, InPlaceType<OwnedInt>, const OwnedInt&>::value, "lvalue construction requires a copyable alternative");
static_assert(noexcept(Scalar(InPlaceType<int>{}, 1)), "tagged builtin construction is nonthrowing");
static_assert(alignof(Variant<Wide, char>) >= alignof(Wide), "over-aligned storage");
static_assert(sizeof(Variant<Wide, char>) >= sizeof(Wide), "inline storage");
static_assert(sizeof(Large) > sizeof(Wide) && alignof(Large) < alignof(Wide), "size and alignment maxima differ");
static_assert(alignof(Variant<Wide, Large>) >= alignof(Wide), "alignment maximum with Wide first");
static_assert(alignof(Variant<Large, Wide>) >= alignof(Wide), "alignment maximum with Wide last");
static_assert(sizeof(Variant<Wide, Large>) >= sizeof(Large), "size maximum with Large last");
static_assert(sizeof(Variant<Large, Wide>) >= sizeof(Large), "size maximum with Large first");
static_assert(std::is_same<decltype(std::declval<Scalar&>().Get<int>()), int&>::value, "lvalue access");
static_assert(std::is_same<decltype(std::declval<const Scalar&>().Get<int>()), const int&>::value, "const lvalue access");
static_assert(std::is_same<decltype(std::declval<Scalar&&>().Get<int>()), int&&>::value, "rvalue access");
static_assert(std::is_same<decltype(std::declval<const Scalar&&>().Get<int>()), const int&&>::value, "const rvalue access");
static_assert(std::is_same<decltype(As<int>(std::declval<Scalar&>())), int&>::value, "mutable As returns lvalue reference");
static_assert(std::is_same<decltype(As<int>(std::declval<const Scalar&>())), const int&>::value, "const As returns lvalue reference");
static_assert(std::is_same<decltype(As<int>(std::declval<Scalar&&>())), int&&>::value, "mutable As returns rvalue reference");
static_assert(std::is_same<decltype(As<int>(std::declval<const Scalar&&>())), const int&&>::value, "const As returns rvalue reference");
static_assert(!noexcept(As<int>(std::declval<Scalar&>())), "mutable As can report inactive alternatives");
static_assert(!noexcept(As<int>(std::declval<const Scalar&>())), "const As can report inactive alternatives");
static_assert(!noexcept(As<int>(std::declval<Scalar&&>())), "rvalue As can report inactive alternatives");
static_assert(!noexcept(As<int>(std::declval<const Scalar&&>())), "const rvalue As can report inactive alternatives");
static_assert(std::is_same<decltype(std::declval<Scalar&>().Is<int>()), bool>::value, "mutable Is returns bool");
static_assert(std::is_same<decltype(std::declval<const Scalar&>().Is<char>()), bool>::value, "const Is returns bool");
static_assert(noexcept(std::declval<Scalar&>().Is<int>()), "mutable Is is nonthrowing");
static_assert(noexcept(std::declval<const Scalar&>().Is<char>()), "const Is is nonthrowing");

struct BorrowState
{
    int alive = 0;
    int destroyed = 0;
};

struct Borrowed
{
    BorrowState* state;
    int value;

    explicit Borrowed(BorrowState& counters, int number) noexcept
        : state(&counters),
          value(number)
    {
        ++state->alive;
    }

    Borrowed(const Borrowed&) = delete;
    Borrowed(Borrowed&&) = delete;
    Borrowed& operator=(const Borrowed&) = delete;
    Borrowed& operator=(Borrowed&&) = delete;

    Borrowed* operator&() noexcept
    {
        return nullptr;
    }

    const Borrowed* operator&() const noexcept
    {
        return nullptr;
    }

    ~Borrowed() noexcept
    {
        ++state->destroyed;
        --state->alive;
    }
};

using References = Variant<Borrowed&, const Borrowed&, int>;
static_assert(!std::is_copy_constructible<References>::value, "borrowed Variant stays move-only");
static_assert(std::is_nothrow_move_constructible<References>::value, "pointee need not move");
static_assert(std::is_nothrow_move_assignable<References>::value, "pointee need not assign");
static_assert(std::is_nothrow_destructible<References>::value, "pointee is not destroyed by Variant");
static_assert(std::is_constructible<References, InPlaceType<Borrowed&>, Borrowed&>::value, "mutable lvalue binding");
static_assert(std::is_constructible<References, InPlaceType<const Borrowed&>, Borrowed&>::value, "mutable to const binding");
static_assert(std::is_constructible<References, InPlaceType<const Borrowed&>, const Borrowed&>::value, "const lvalue binding");
static_assert(!std::is_constructible<References, InPlaceType<Borrowed&>, const Borrowed&>::value, "no const to mutable binding");
static_assert(!std::is_constructible<References, InPlaceType<const Borrowed&>, Borrowed&&>::value, "no temporary binding");
static_assert(!std::is_constructible<References, InPlaceType<const Borrowed&>, const Borrowed&&>::value, "no const rvalue binding");
static_assert(!std::is_constructible<Variant<const int&>, InPlaceType<const int&>, short&>::value, "no conversion temporary");
static_assert(std::is_same<decltype(std::declval<References&>().Get<Borrowed&>()), Borrowed&>::value, "mutable reference Get &");
static_assert(std::is_same<decltype(std::declval<const References&>().Get<Borrowed&>()), Borrowed&>::value, "mutable reference Get const&");
static_assert(std::is_same<decltype(std::declval<References&&>().Get<Borrowed&>()), Borrowed&>::value, "mutable reference Get &&");
static_assert(std::is_same<decltype(std::declval<const References&&>().Get<Borrowed&>()), Borrowed&>::value, "mutable reference Get const&&");
static_assert(std::is_same<decltype(std::declval<References&>().Get<const Borrowed&>()), const Borrowed&>::value, "const reference Get &");
static_assert(std::is_same<decltype(std::declval<const References&>().Get<const Borrowed&>()), const Borrowed&>::value, "const reference Get const&");
static_assert(std::is_same<decltype(std::declval<References&&>().Get<const Borrowed&>()), const Borrowed&>::value, "const reference Get &&");
static_assert(std::is_same<decltype(std::declval<const References&&>().Get<const Borrowed&>()), const Borrowed&>::value, "const reference Get const&&");
static_assert(std::is_same<decltype(As<Borrowed&>(std::declval<References&>())), Borrowed&>::value, "mutable reference As &");
static_assert(std::is_same<decltype(As<Borrowed&>(std::declval<const References&>())), Borrowed&>::value, "mutable reference As const&");
static_assert(std::is_same<decltype(As<Borrowed&>(std::declval<References&&>())), Borrowed&>::value, "mutable reference As &&");
static_assert(std::is_same<decltype(As<Borrowed&>(std::declval<const References&&>())), Borrowed&>::value, "mutable reference As const&&");
static_assert(std::is_same<decltype(As<const Borrowed&>(std::declval<References&>())), const Borrowed&>::value, "const reference As &");
static_assert(std::is_same<decltype(As<const Borrowed&>(std::declval<const References&>())), const Borrowed&>::value, "const reference As const&");
static_assert(std::is_same<decltype(As<const Borrowed&>(std::declval<References&&>())), const Borrowed&>::value, "const reference As &&");
static_assert(std::is_same<decltype(As<const Borrowed&>(std::declval<const References&&>())), const Borrowed&>::value, "const reference As const&&");

struct Counters
{
    int alive = 0;
    int constructed = 0;
    int destroyed = 0;
    int copies = 0;
    int moves = 0;
    int moveAssignments = 0;
    bool throwCopy = false;
};

struct Tracked
{
    Counters* counters;
    int value;

    explicit Tracked(Counters& state, int number) noexcept
        : counters(&state),
          value(number)
    {
        ++counters->alive;
        ++counters->constructed;
    }

    Tracked(const Tracked& other)
        : counters(other.counters),
          value(other.value)
    {
        ++counters->copies;
        if (counters->throwCopy)
        {
            throw std::runtime_error("copy construction");
        }
        ++counters->alive;
        ++counters->constructed;
    }

    Tracked(Tracked&& other) noexcept
        : counters(other.counters),
          value(other.value)
    {
        ++counters->moves;
        other.value = -1;
        ++counters->alive;
        ++counters->constructed;
    }

    Tracked& operator=(Tracked&& other) noexcept
    {
        ++counters->moveAssignments;
        value = other.value;
        other.value = -1;
        return *this;
    }

    ~Tracked() noexcept
    {
        ++counters->destroyed;
        --counters->alive;
    }
};

struct PlacementState
{
    int alive = 0;
    int constructed = 0;
    int destroyed = 0;
    int moves = 0;
};

struct AdversarialPlacement
{
    PlacementState* state;
    int value;

    static int& PlacementCalls() noexcept
    {
        static int calls = 0;
        return calls;
    }

    // A legal class-specific overload: it records a regression without
    // redirecting construction away from the supplied inline storage.
    static void* operator new(std::size_t, void* destination) noexcept
    {
        ++PlacementCalls();
        return destination;
    }

    explicit AdversarialPlacement(PlacementState& counters, int number) noexcept
        : state(&counters),
          value(number)
    {
        ++state->alive;
        ++state->constructed;
    }

    AdversarialPlacement(AdversarialPlacement&& other) noexcept
        : state(other.state),
          value(other.value)
    {
        ++state->moves;
        ++state->alive;
        ++state->constructed;
    }

    AdversarialPlacement& operator=(AdversarialPlacement&& other) noexcept
    {
        value = other.value;
        return *this;
    }

    ~AdversarialPlacement() noexcept
    {
        ++state->destroyed;
        --state->alive;
    }
};

using Observable = Variant<Tracked, int>;
static_assert(!std::is_copy_constructible<Observable>::value, "copyable payload still has move-only Variant");
static_assert(!std::is_copy_assignable<Observable>::value, "copy assignment stays disabled");
static_assert(std::is_nothrow_move_constructible<Observable>::value, "nonthrowing payload move");
static_assert(std::is_nothrow_move_assignable<Observable>::value, "nonthrowing payload assignment");
static_assert(!std::is_nothrow_constructible<Observable, InPlaceType<Tracked>, Tracked&>::value, "lvalue copy can throw");
static_assert(std::is_nothrow_constructible<Observable, InPlaceType<Tracked>, Tracked&&>::value, "rvalue construction follows move");

TEST(VariantTest, GlobalPlacementConstructionBypassesClassOverload)
{
    PlacementState state;
    AdversarialPlacement::PlacementCalls() = 0;
    {
        using Adversarial = Variant<AdversarialPlacement, int>;
        Adversarial source(InPlaceType<AdversarialPlacement>{}, AdversarialPlacement(state, 1));
        EXPECT_EQ(0, AdversarialPlacement::PlacementCalls());
        EXPECT_EQ(2, state.constructed);
        EXPECT_EQ(1, state.moves);
        EXPECT_EQ(1, state.destroyed);
        EXPECT_EQ(1, state.alive);

        Adversarial moved(std::move(source));
        EXPECT_EQ(0, AdversarialPlacement::PlacementCalls());
        EXPECT_EQ(3, state.constructed);
        EXPECT_EQ(2, state.moves);
        EXPECT_EQ(2, state.destroyed);
        EXPECT_EQ(1, state.alive);

        Adversarial replacement(InPlaceType<int>{}, 9);
        replacement = std::move(moved);
        EXPECT_EQ(0, AdversarialPlacement::PlacementCalls());
        EXPECT_EQ(4, state.constructed);
        EXPECT_EQ(3, state.moves);
        EXPECT_EQ(3, state.destroyed);
        EXPECT_EQ(1, state.alive);
        EXPECT_TRUE(replacement.Is<AdversarialPlacement>());
    }
    EXPECT_EQ(0, AdversarialPlacement::PlacementCalls());
    EXPECT_EQ(0, state.alive);
    EXPECT_EQ(4, state.constructed);
    EXPECT_EQ(4, state.destroyed);
}

TEST(VariantTest, BorrowedReferencesHaveLogicalAccessInEveryCategory)
{
    BorrowState state;
    Borrowed first(state, 11);
    const Borrowed second(state, 22);
    References mutableRef(InPlaceType<Borrowed&>{}, first);
    const References& constView = mutableRef;
    EXPECT_TRUE(mutableRef.Is<Borrowed&>());
    EXPECT_FALSE(mutableRef.Is<const Borrowed&>());
    EXPECT_EQ(std::addressof(first), std::addressof(mutableRef.Get<Borrowed&>()));
    EXPECT_EQ(std::addressof(first), std::addressof(constView.Get<Borrowed&>()));
    EXPECT_EQ(std::addressof(first), std::addressof(std::move(mutableRef).Get<Borrowed&>()));
    EXPECT_EQ(std::addressof(first), std::addressof(std::move(constView).Get<Borrowed&>()));
    EXPECT_EQ(std::addressof(first), std::addressof(As<Borrowed&>(mutableRef)));
    EXPECT_EQ(std::addressof(first), std::addressof(As<Borrowed&>(constView)));
    EXPECT_EQ(std::addressof(first), std::addressof(As<Borrowed&>(std::move(mutableRef))));
    EXPECT_EQ(std::addressof(first), std::addressof(As<Borrowed&>(std::move(constView))));
    constView.Get<Borrowed&>().value = 12;
    EXPECT_EQ(12, first.value);

    const References constRef(InPlaceType<const Borrowed&>{}, second);
    EXPECT_TRUE(constRef.Is<const Borrowed&>());
    EXPECT_FALSE(constRef.Is<Borrowed&>());
    EXPECT_EQ(std::addressof(second), std::addressof(constRef.Get<const Borrowed&>()));
    EXPECT_EQ(std::addressof(second), std::addressof(std::move(constRef).Get<const Borrowed&>()));
    EXPECT_EQ(std::addressof(second), std::addressof(As<const Borrowed&>(constRef)));
    EXPECT_EQ(std::addressof(second), std::addressof(As<const Borrowed&>(std::move(constRef))));
    References mutableConstRef(InPlaceType<const Borrowed&>{}, first);
    const References& constConstRef = mutableConstRef;
    EXPECT_EQ(std::addressof(first), std::addressof(mutableConstRef.Get<const Borrowed&>()));
    EXPECT_EQ(std::addressof(first), std::addressof(constConstRef.Get<const Borrowed&>()));
    EXPECT_EQ(std::addressof(first), std::addressof(std::move(mutableConstRef).Get<const Borrowed&>()));
    EXPECT_EQ(std::addressof(first), std::addressof(std::move(constConstRef).Get<const Borrowed&>()));
    EXPECT_EQ(std::addressof(first), std::addressof(As<const Borrowed&>(mutableConstRef)));
    EXPECT_EQ(std::addressof(first), std::addressof(As<const Borrowed&>(constConstRef)));
    EXPECT_EQ(std::addressof(first), std::addressof(As<const Borrowed&>(std::move(mutableConstRef))));
    EXPECT_EQ(std::addressof(first), std::addressof(As<const Borrowed&>(std::move(constConstRef))));
    EXPECT_THROW(mutableRef.Get<const Borrowed&>(), std::logic_error);
    EXPECT_THROW(constView.Get<const Borrowed&>(), std::logic_error);
    EXPECT_THROW(std::move(mutableRef).Get<const Borrowed&>(), std::logic_error);
    EXPECT_THROW(std::move(constView).Get<const Borrowed&>(), std::logic_error);
    EXPECT_THROW(As<const Borrowed&>(mutableRef), std::logic_error);
    EXPECT_THROW(As<const Borrowed&>(constView), std::logic_error);
    EXPECT_THROW(As<const Borrowed&>(std::move(mutableRef)), std::logic_error);
    EXPECT_THROW(As<const Borrowed&>(std::move(constView)), std::logic_error);
    EXPECT_THROW(constRef.Get<Borrowed&>(), std::logic_error);
    EXPECT_THROW(As<Borrowed&>(constRef), std::logic_error);
    EXPECT_EQ(2, state.alive);
    EXPECT_EQ(0, state.destroyed);
}

TEST(VariantTest, BorrowedBindingsRebindWithoutTouchingPointees)
{
    BorrowState state;
    Borrowed first(state, 1);
    Borrowed second(state, 2);
    const Borrowed third(state, 3);
    {
        References source(InPlaceType<Borrowed&>{}, first);
        References destination(InPlaceType<Borrowed&>{}, second);
        destination = std::move(source);
        EXPECT_EQ(std::addressof(first), std::addressof(destination.Get<Borrowed&>()));
        EXPECT_EQ(2, second.value);
        References& self = destination;
        destination = std::move(self);
        EXPECT_EQ(std::addressof(first), std::addressof(destination.Get<Borrowed&>()));
        References moved(std::move(destination));
        EXPECT_EQ(std::addressof(first), std::addressof(moved.Get<Borrowed&>()));
        destination = References(InPlaceType<const Borrowed&>{}, third);
        EXPECT_TRUE(destination.Is<const Borrowed&>());
        EXPECT_FALSE(destination.Is<Borrowed&>());
        source = References(InPlaceType<int>{}, 4);
        EXPECT_TRUE(source.Is<int>());
        moved = std::move(destination);
        EXPECT_EQ(std::addressof(third), std::addressof(moved.Get<const Borrowed&>()));
        destination = References(InPlaceType<Borrowed&>{}, second);
        EXPECT_EQ(std::addressof(second), std::addressof(destination.Get<Borrowed&>()));
    }
    EXPECT_EQ(3, state.alive);
    EXPECT_EQ(0, state.destroyed);
    EXPECT_EQ(1, first.value);
    EXPECT_EQ(2, second.value);
    EXPECT_EQ(3, third.value);
}

TEST(VariantTest, OwnedAndBorrowedTransitionsDestroyOnlyOwnedStorage)
{
    Counters state;
    {
        Tracked referent(state, 7);
        Tracked seed(state, 9);
        using Mixed = Variant<Tracked, Tracked&, const Tracked&>;
        Mixed owned(InPlaceType<Tracked>{}, seed);
        Mixed ref(InPlaceType<Tracked&>{}, referent);
        EXPECT_EQ(3, state.constructed);
        EXPECT_EQ(1, state.copies);
        owned = std::move(ref);
        EXPECT_EQ(1, state.destroyed);
        EXPECT_EQ(2, state.alive);
        EXPECT_EQ(std::addressof(referent), std::addressof(owned.Get<Tracked&>()));
        Mixed newOwned(InPlaceType<Tracked>{}, seed);
        ref = std::move(newOwned);
        EXPECT_EQ(1, state.moves);
        EXPECT_EQ(3, state.alive);
        EXPECT_EQ(2, state.destroyed);
        ref = std::move(owned);
        EXPECT_EQ(3, state.destroyed);
        EXPECT_EQ(2, state.alive);
        EXPECT_TRUE(ref.Is<Tracked&>());
        EXPECT_FALSE(ref.Is<Tracked>());
        owned = Mixed(InPlaceType<const Tracked&>{}, referent);
        EXPECT_EQ(std::addressof(referent), std::addressof(owned.Get<const Tracked&>()));
        EXPECT_EQ(1, state.moves);
        EXPECT_EQ(0, state.moveAssignments);
    }
    EXPECT_EQ(0, state.alive);
    EXPECT_EQ(state.constructed, state.destroyed);
}

TEST(VariantTest, FindIndexCanBeOdrUsed)
{
    const volatile std::size_t& found = TypeTraits::Find<int, char, int>::Index;
    const volatile std::size_t* absent = &TypeTraits::Find<int>::Index;
    const std::size_t foundIndex = found;
    const std::size_t absentIndex = *absent;
    EXPECT_EQ(1u, foundIndex);
    EXPECT_EQ(0u, absentIndex);
}

TEST(VariantTest, IsQueriesActiveAndInactiveAlternatives)
{
    Scalar mutableValue(InPlaceType<int>{}, 41);
    EXPECT_TRUE(mutableValue.Is<int>());
    EXPECT_FALSE(mutableValue.Is<char>());
    const Scalar& constView = mutableValue;
    EXPECT_TRUE(constView.Is<int>());
    EXPECT_FALSE(constView.Is<char>());

    const Scalar constValue(InPlaceType<char>{}, 'x');
    EXPECT_TRUE(constValue.Is<char>());
    EXPECT_FALSE(constValue.Is<int>());
}

TEST(VariantTest, IsTracksMoveDestinationsAndReinitializedSources)
{
    Scalar source(InPlaceType<int>{}, 7);
    Scalar moved(std::move(source));
    EXPECT_TRUE(moved.Is<int>());
    EXPECT_FALSE(moved.Is<char>());

    source = Scalar(InPlaceType<char>{}, 'a');
    EXPECT_TRUE(source.Is<char>());
    EXPECT_FALSE(source.Is<int>());

    Scalar sameAlternative(InPlaceType<int>{}, 0);
    sameAlternative = std::move(moved);
    EXPECT_TRUE(sameAlternative.Is<int>());
    EXPECT_FALSE(sameAlternative.Is<char>());

    moved = Scalar(InPlaceType<char>{}, 'b');
    EXPECT_TRUE(moved.Is<char>());
    EXPECT_FALSE(moved.Is<int>());

    sameAlternative = std::move(moved);
    EXPECT_TRUE(sameAlternative.Is<char>());
    EXPECT_FALSE(sameAlternative.Is<int>());

    moved = Scalar(InPlaceType<int>{}, 9);
    EXPECT_TRUE(moved.Is<int>());
    EXPECT_FALSE(moved.Is<char>());
}

TEST(VariantTest, ExactAccessAndAlignment)
{
    Scalar value(InPlaceType<const int>{}, 41);
    EXPECT_EQ(41, value.Get<int>());
    value.Get<int>() = 42;
    EXPECT_EQ(42, static_cast<const Scalar&>(value).Get<int>());
    EXPECT_EQ(42, std::move(value).Get<int>());
    EXPECT_EQ(42, std::move(static_cast<const Scalar&>(value)).Get<int>());
    EXPECT_THROW(value.Get<char>(), std::logic_error);
    EXPECT_THROW(static_cast<const Scalar&>(value).Get<char>(), std::logic_error);
    EXPECT_THROW(std::move(value).Get<char>(), std::logic_error);
    EXPECT_THROW(std::move(static_cast<const Scalar&>(value)).Get<char>(), std::logic_error);

    Variant<Wide, char> aligned(InPlaceType<Wide>{}, Wide{});
    EXPECT_EQ(0u, reinterpret_cast<std::uintptr_t>(&aligned.Get<Wide>()) % alignof(Wide));

    Variant<Wide, Large> wideFirst(InPlaceType<Wide>{}, Wide{});
    EXPECT_EQ(0u, reinterpret_cast<std::uintptr_t>(&wideFirst.Get<Wide>()) % alignof(Wide));
    Large large{};
    large.data[512] = 'x';
    wideFirst = Variant<Wide, Large>(InPlaceType<Large>{}, std::move(large));
    EXPECT_EQ('x', wideFirst.Get<Large>().data[512]);

    Variant<Large, Wide> wideLast(InPlaceType<Large>{}, Large{});
    wideLast.Get<Large>().data[512] = 'y';
    EXPECT_EQ('y', wideLast.Get<Large>().data[512]);
    wideLast = Variant<Large, Wide>(InPlaceType<Wide>{}, Wide{});
    EXPECT_EQ(0u, reinterpret_cast<std::uintptr_t>(&wideLast.Get<Wide>()) % alignof(Wide));
}

TEST(VariantTest, PublicAsChecksEveryValueCategory)
{
    Scalar value(InPlaceType<int>{}, 41);
    As<int>(value) = 42;
    const Scalar& constView = value;
    EXPECT_EQ(42, As<int>(constView));
    EXPECT_EQ(42, As<int>(std::move(value)));
    EXPECT_EQ(42, As<int>(std::move(constView)));

    EXPECT_THROW(As<char>(value), std::logic_error);
    EXPECT_THROW(As<char>(constView), std::logic_error);
    EXPECT_THROW(As<char>(std::move(value)), std::logic_error);
    EXPECT_THROW(As<char>(std::move(constView)), std::logic_error);

    const Scalar constValue(InPlaceType<char>{}, 'x');
    EXPECT_EQ('x', As<char>(constValue));
    EXPECT_EQ('x', As<char>(std::move(constValue)));
    EXPECT_THROW(As<int>(constValue), std::logic_error);
    EXPECT_THROW(As<int>(std::move(constValue)), std::logic_error);
}

TEST(VariantTest, PublicAsMovesOwnerWithoutEndingSourceLifetime)
{
    int deletions = 0;
    {
        Owner source(InPlaceType<OwnedInt>{}, OwnedInt(new int(12), CountingDeleter{&deletions}));
        OwnedInt extracted = As<OwnedInt>(std::move(source));
        ASSERT_TRUE(extracted);
        EXPECT_EQ(12, *extracted);
        source = Owner(InPlaceType<char>{}, 'x');
        EXPECT_EQ('x', As<char>(source));
        EXPECT_EQ(0, deletions);
    }
    EXPECT_EQ(1, deletions);
}

TEST(VariantTest, TaggedLvalueCopyFailureDoesNotCreateVariant)
{
    Counters state;
    {
        Tracked seed(state, 10);
        state.throwCopy = true;
        EXPECT_THROW(Observable failed(InPlaceType<Tracked>{}, seed), std::runtime_error);
        EXPECT_EQ(1, state.alive);
        EXPECT_EQ(1, state.constructed);
        EXPECT_EQ(0, state.destroyed);
        state.throwCopy = false;
        Observable good(InPlaceType<Tracked>{}, seed);
        EXPECT_EQ(10, good.Get<Tracked>().value);
        EXPECT_EQ(2, state.copies);
    }
    EXPECT_EQ(0, state.alive);
    EXPECT_EQ(state.constructed, state.destroyed);
}

TEST(VariantTest, MoveConstructionConsumesSource)
{
    Counters state;
    {
        Tracked seed(state, 23);
        Observable source(InPlaceType<Tracked>{}, seed);
        const int beforeMove = state.destroyed;
        Observable moved(std::move(source));
        EXPECT_EQ(23, moved.Get<Tracked>().value);
        EXPECT_EQ(1, state.moves);
        // Just after the move there are two live Tracked objects (seed and
        // moved's payload), not three: the move destroyed source's payload.
        EXPECT_EQ(2, state.alive);
        EXPECT_EQ(beforeMove + 1, state.destroyed);
        const int beforeReassignment = state.destroyed;
        source = Observable(InPlaceType<int>{}, 0);
        EXPECT_EQ(beforeReassignment, state.destroyed);
        EXPECT_EQ(0, source.Get<int>());
    }
    EXPECT_EQ(0, state.alive);
    EXPECT_EQ(state.constructed, state.destroyed);
}

TEST(VariantTest, SameAlternativeMoveAssignsAndSelfMoveDoesNothing)
{
    Counters state;
    {
        Tracked seed(state, 9);
        Observable source(InPlaceType<Tracked>{}, seed);
        Observable destination(InPlaceType<Tracked>{}, seed);
        destination = std::move(source);
        EXPECT_EQ(9, destination.Get<Tracked>().value);
        EXPECT_EQ(1, state.moveAssignments);
        // The source's own payload is destroyed once it is replaced.
        EXPECT_EQ(1, state.destroyed);
        Observable& alias = destination;
        destination = std::move(alias);
        EXPECT_EQ(9, destination.Get<Tracked>().value);
        EXPECT_EQ(1, state.moveAssignments);
        source = Observable(InPlaceType<int>{}, 3);
        EXPECT_EQ(3, source.Get<int>());
    }
    EXPECT_EQ(0, state.alive);
    EXPECT_EQ(state.constructed, state.destroyed);
}

TEST(VariantTest, CrossAlternativeMoveReplacesExactlyOnce)
{
    Counters state;
    {
        Tracked seed(state, 6);
        Observable source(InPlaceType<Tracked>{}, seed);
        Observable destination(InPlaceType<int>{}, 1);
        destination = std::move(source);
        EXPECT_EQ(6, destination.Get<Tracked>().value);
        EXPECT_EQ(1, state.moves);
        EXPECT_EQ(0, state.moveAssignments);
        destination = Observable(InPlaceType<int>{}, 7);
        EXPECT_EQ(7, destination.Get<int>());
        EXPECT_EQ(2, state.destroyed);
        source = Observable(InPlaceType<int>{}, 8);
        EXPECT_EQ(8, source.Get<int>());
    }
    EXPECT_EQ(0, state.alive);
    EXPECT_EQ(state.constructed, state.destroyed);
}

TEST(VariantTest, MovedFromSourceAssignedIntoLiveDestinationSameAlternativeDestroysOnce)
{
    Counters state;
    {
        Tracked seed(state, 1);
        Tracked other(state, 2);
        Observable source(InPlaceType<Tracked>{}, seed);
        Observable moved(std::move(source));

        Observable destination(InPlaceType<Tracked>{}, other);
        const int beforeAssignment = state.destroyed;
        destination = std::move(source);
        EXPECT_EQ(beforeAssignment + 1, state.destroyed);
    }
    EXPECT_EQ(0, state.alive);
    EXPECT_EQ(state.constructed, state.destroyed);
}

TEST(VariantTest, MovedFromSourceAssignedIntoLiveDestinationDifferentAlternativeDestroysOnce)
{
    Counters state;
    {
        Observable source(InPlaceType<int>{}, 11);
        Observable moved(std::move(source));

        Tracked seed(state, 3);
        Observable destination(InPlaceType<Tracked>{}, seed);
        const int beforeAssignment = state.destroyed;
        destination = std::move(source);
        EXPECT_EQ(beforeAssignment + 1, state.destroyed);
    }
    EXPECT_EQ(0, state.alive);
    EXPECT_EQ(state.constructed, state.destroyed);
}

TEST(VariantTest, LiveSourceAssignedIntoMovedFromDestinationReinitializes)
{
    Counters state;
    {
        Tracked seed(state, 5);
        Observable destinationSource(InPlaceType<Tracked>{}, seed);
        Observable destination(std::move(destinationSource));
        Observable movedFromDestination(std::move(destination));

        Observable live(InPlaceType<int>{}, 21);
        destination = std::move(live);
        EXPECT_TRUE(destination.Is<int>());
        EXPECT_EQ(21, destination.Get<int>());
    }
    EXPECT_EQ(0, state.alive);
    EXPECT_EQ(state.constructed, state.destroyed);
}

TEST(VariantTest, MoveOnlyResourceOwnership)
{
    int deletions = 0;
    {
        Owner source(InPlaceType<OwnedInt>{}, OwnedInt(new int(12), CountingDeleter{&deletions}));
        Owner destination(std::move(source));
        ASSERT_TRUE(destination.Get<OwnedInt>());
        EXPECT_EQ(12, *destination.Get<OwnedInt>());
        source = Owner(InPlaceType<char>{}, 'x');
        EXPECT_EQ('x', source.Get<char>());
        Owner another(InPlaceType<char>{}, 'y');
        another = std::move(destination);
        ASSERT_TRUE(another.Get<OwnedInt>());
        EXPECT_EQ(12, *another.Get<OwnedInt>());
        destination = Owner(InPlaceType<char>{}, 'z');
        EXPECT_EQ('z', destination.Get<char>());
        EXPECT_EQ(0, deletions);
    }
    EXPECT_EQ(1, deletions);
}
} // namespace

namespace
{
struct MutableVisit
{
    int operator()(int& value) const
    {
        ++value;
        return value;
    }
    int operator()(char& value) const
    {
        value = 'z';
        return value;
    }
};
struct ConstVisit
{
    int operator()(const int& value) const
    {
        return value + 1;
    }
    int operator()(const char& value) const
    {
        return value;
    }
};
struct ReferenceVisit
{
    int operator()(int& value) const
    {
        value += 2;
        return value;
    }
    int operator()(const long& value) const
    {
        return static_cast<int>(value);
    }
};
struct VoidVisit
{
    void operator()(int& value) const
    {
        value = 42;
    }
    void operator()(char& value) const
    {
        value = 'x';
    }
};
} // namespace

TEST(VariantTest, ExhaustiveVisitDispatchesMutableConstAndReferenceAlternatives)
{
    Scalar number(InPlaceType<int>{}, 3);
    Scalar letter(InPlaceType<char>{}, 'a');
    EXPECT_EQ(4, number.Visit<int>(MutableVisit{}));
    EXPECT_EQ(static_cast<int>('z'), letter.Visit<int>(MutableVisit{}));
    const Scalar& constNumber = number;
    const Scalar& constLetter = letter;
    EXPECT_EQ(5, constNumber.Visit<int>(ConstVisit{}));
    EXPECT_EQ(static_cast<int>('z'), constLetter.Visit<int>(ConstVisit{}));
    number.Visit<void>(VoidVisit{});
    EXPECT_EQ(42, number.Get<int>());
    int referent = 5;
    const long immutable = 9;
    Variant<int&, const long&> mutableReference(InPlaceType<int&>{}, referent);
    Variant<int&, const long&> constReference(InPlaceType<const long&>{}, immutable);
    const auto& constView = mutableReference;
    EXPECT_EQ(7, constView.Visit<int>(ReferenceVisit{}));
    EXPECT_EQ(7, referent); // A const Variant does not const-qualify a referent.
    EXPECT_EQ(9, constReference.Visit<int>(ReferenceVisit{}));
}
