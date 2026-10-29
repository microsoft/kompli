// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Variant.h"

#include "TypeTraits.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>

using ComplianceEngine::InPlaceType;
using ComplianceEngine::MovableVariant;
using ComplianceEngine::Variant;
namespace TypeTraits = ComplianceEngine::TypeTraits;

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
// Unsupported lists fail MovableVariant's class-level assertions: Variant<>,
// Variant<int, const int>, Variant<int&>, Variant<void>, Variant<ThrowingMove>,
// Variant<NoMoveAssignment>, and Variant<ThrowingDestructor>.
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

using Observable = Variant<Tracked, int>;
static_assert(!std::is_copy_constructible<Observable>::value, "copyable payload still has move-only Variant");
static_assert(!std::is_copy_assignable<Observable>::value, "copy assignment stays disabled");
static_assert(std::is_nothrow_move_constructible<Observable>::value, "nonthrowing payload move");
static_assert(std::is_nothrow_move_assignable<Observable>::value, "nonthrowing payload assignment");
static_assert(!std::is_nothrow_constructible<Observable, InPlaceType<Tracked>, Tracked&>::value, "lvalue copy can throw");
static_assert(std::is_nothrow_constructible<Observable, InPlaceType<Tracked>, Tracked&&>::value, "rvalue construction follows move");

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

TEST(VariantTest, MoveConstructionRetainsSourceLifetime)
{
    Counters state;
    {
        Tracked seed(state, 23);
        Observable source(InPlaceType<Tracked>{}, seed);
        Observable moved(std::move(source));
        EXPECT_EQ(23, moved.Get<Tracked>().value);
        EXPECT_EQ(1, state.moves);
        EXPECT_EQ(3, state.alive);
        const int beforeReassignment = state.destroyed;
        source = Observable(InPlaceType<int>{}, 0);
        EXPECT_EQ(beforeReassignment + 1, state.destroyed);
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
        EXPECT_EQ(0, state.destroyed);
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
        EXPECT_EQ(1, state.destroyed);
        source = Observable(InPlaceType<int>{}, 8);
        EXPECT_EQ(8, source.Get<int>());
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
