// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_VARIANT_HPP
#define COMPLIANCEENGINE_VARIANT_HPP

#include "TypeTraits.h"

#include <cstddef>
#include <memory>
#include <new> // IWYU pragma: keep - included transitively, but needed for portability
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace ComplianceEngine
{
template <typename T>
struct InPlaceType
{
};

namespace VariantDetail
{
// Precondition: storage contains a live, correctly aligned T; no active-type check.
template <typename T>
T& As(void* storage) noexcept
{
    return *static_cast<T*>(storage);
}

template <typename T>
const T& As(const void* storage) noexcept
{
    return *static_cast<const T*>(storage);
}

// Logical references are represented by pointers; constness of the Variant
// must not change the cv qualification of the bound object.
template <typename T, bool IsReference = std::is_lvalue_reference<T>::value>
struct Storage
{
    using Type = T;

    template <typename U>
    static void Construct(void* storage, U&& value)
    {
        ::new (storage) T(std::forward<U>(value));
    }

    static T& Get(void* storage) noexcept
    {
        return As<T>(storage);
    }

    static const T& Get(const void* storage) noexcept
    {
        return As<T>(storage);
    }
};

template <typename T>
struct Storage<T, true>
{
    using Type = typename std::add_pointer<typename std::remove_reference<T>::type>::type;

    template <typename U>
    static void Construct(void* storage, U&& value) noexcept
    {
        ::new (storage) Type(std::addressof(value));
    }

    static T Get(void* storage) noexcept
    {
        return *As<Type>(storage);
    }

    static T Get(const void* storage) noexcept
    {
        return *As<Type>(storage);
    }
};

// Dispatch only the lifetime operations needed by the nonthrowing move profile.
template <std::size_t Index, typename... Alternatives>
struct Dispatch;

template <std::size_t Index, typename First, typename... Rest>
struct Dispatch<Index, First, Rest...>
{
    static void MoveConstruct(std::size_t active, void* destination, void* source) noexcept
    {
        if (Index == active)
        {
            using Stored = typename Storage<First>::Type;
            ::new (destination) Stored(std::move(As<Stored>(source)));
        }
        else
        {
            Dispatch<Index + 1, Rest...>::MoveConstruct(active, destination, source);
        }
    }

    static void MoveAssign(std::size_t active, void* destination, void* source) noexcept
    {
        if (Index == active)
        {
            using Stored = typename Storage<First>::Type;
            As<Stored>(destination) = std::move(As<Stored>(source));
        }
        else
        {
            Dispatch<Index + 1, Rest...>::MoveAssign(active, destination, source);
        }
    }

    static void Destroy(std::size_t active, void* storage) noexcept
    {
        if (Index == active)
        {
            using Stored = typename Storage<First>::Type;
            As<Stored>(storage).~Stored();
        }
        else
        {
            Dispatch<Index + 1, Rest...>::Destroy(active, storage);
        }
    }
};

template <std::size_t Index, typename Last>
struct Dispatch<Index, Last>
{
    static void MoveConstruct(std::size_t, void* destination, void* source) noexcept
    {
        using Stored = typename Storage<Last>::Type;
        ::new (destination) Stored(std::move(As<Stored>(source)));
    }

    static void MoveAssign(std::size_t, void* destination, void* source) noexcept
    {
        using Stored = typename Storage<Last>::Type;
        As<Stored>(destination) = std::move(As<Stored>(source));
    }

    static void Destroy(std::size_t, void* storage) noexcept
    {
        using Stored = typename Storage<Last>::Type;
        As<Stored>(storage).~Stored();
    }
};
// The visitor is checked for *every* alternative at instantiation, even
// when the currently active index would take a different branch.
template <typename R, typename Visitor, typename Pointer, std::size_t Index, typename... Types>
struct VisitDispatch;

template <typename R, typename Visitor, typename Pointer, std::size_t Index, typename First, typename... Rest>
struct VisitDispatch<R, Visitor, Pointer, Index, First, Rest...>
{
    static R Apply(std::size_t active, Pointer storage, Visitor& visitor)
    {
        if (active == Index)
            return visitor(Storage<First>::Get(storage));
        return VisitDispatch<R, Visitor, Pointer, Index + 1, Rest...>::Apply(active, storage, visitor);
    }
};

template <typename R, typename Visitor, typename Pointer, std::size_t Index, typename Last>
struct VisitDispatch<R, Visitor, Pointer, Index, Last>
{
    static R Apply(std::size_t, Pointer storage, Visitor& visitor)
    {
        return visitor(Storage<Last>::Get(storage));
    }
};
} // namespace VariantDetail

template <typename... Alternatives>
class MovableVariant
{
    static_assert(0 < sizeof...(Alternatives), "Variant requires at least one alternative");
    static_assert(TypeTraits::Unique<Alternatives...>::value, "Variant alternatives must be distinct, ignoring cv");
    static_assert(TypeTraits::All<!std::is_rvalue_reference<Alternatives>::value...>::value, "Variant cannot hold rvalue references");
    static_assert(TypeTraits::All<!std::is_void<Alternatives>::value...>::value, "Variant cannot hold void");
    static_assert(TypeTraits::All<std::is_nothrow_move_constructible<typename VariantDetail::Storage<Alternatives>::Type>::value...>::value,
        "Variant requires nonthrowing move constructors");
    static_assert(TypeTraits::All<std::is_nothrow_move_assignable<typename VariantDetail::Storage<Alternatives>::Type>::value...>::value,
        "Variant requires nonthrowing move assignment");
    static_assert(TypeTraits::All<std::is_nothrow_destructible<typename VariantDetail::Storage<Alternatives>::Type>::value...>::value,
        "Variant requires nonthrowing destructors");

    alignas(TypeTraits::Max(alignof(
        typename VariantDetail::Storage<Alternatives>::Type)...)) char mStorage[TypeTraits::Max(sizeof(typename VariantDetail::Storage<Alternatives>::Type)...)];
    std::size_t mIndex;

public:
    template <typename T, typename U,
        typename std::enable_if<(1 == TypeTraits::Count<T, Alternatives...>::value) &&
                                    std::is_same<typename std::remove_cv<typename std::remove_reference<T>::type>::type, typename std::remove_cv<typename std::remove_reference<U>::type>::type>::value &&
                                    std::is_constructible<typename TypeTraits::Find<T, Alternatives...>::Type, U&&>::value && (!std::is_lvalue_reference<T>::value || std::is_lvalue_reference<U&&>::value),
            int>::type = 0>
    explicit MovableVariant(InPlaceType<T>, U&& value) noexcept(std::is_nothrow_constructible<typename TypeTraits::Find<T, Alternatives...>::Type, U&&>::value)
        : mIndex(TypeTraits::Find<T, Alternatives...>::Index)
    {
        using Selected = typename TypeTraits::Find<T, Alternatives...>::Type;
        // A failed lvalue copy never completes construction of a Variant.
        VariantDetail::Storage<Selected>::Construct(static_cast<void*>(mStorage), std::forward<U>(value));
    }

    ~MovableVariant() noexcept
    {
        VariantDetail::Dispatch<0, Alternatives...>::Destroy(mIndex, mStorage);
    }

    MovableVariant(const MovableVariant&) = delete;
    MovableVariant& operator=(const MovableVariant&) = delete;

    MovableVariant(MovableVariant&& other) noexcept
        : mIndex(other.mIndex)
    {
        VariantDetail::Dispatch<0, Alternatives...>::MoveConstruct(mIndex, mStorage, other.mStorage);
    }

    MovableVariant& operator=(MovableVariant&& other) noexcept
    {
        if (this == &other)
        {
            return *this;
        }
        if (mIndex == other.mIndex)
        {
            VariantDetail::Dispatch<0, Alternatives...>::MoveAssign(mIndex, mStorage, other.mStorage);
        }
        else
        {
            VariantDetail::Dispatch<0, Alternatives...>::Destroy(mIndex, mStorage);
            VariantDetail::Dispatch<0, Alternatives...>::MoveConstruct(other.mIndex, mStorage, other.mStorage);
            mIndex = other.mIndex;
        }
        return *this;
    }

    template <typename T>
    T& Get() &
    {
        Check<T>();
        return VariantDetail::Storage<T>::Get(static_cast<void*>(mStorage));
    }

    template <typename T>
    const T& Get() const&
    {
        Check<T>();
        return VariantDetail::Storage<T>::Get(static_cast<const void*>(mStorage));
    }

    template <typename T>
    T&& Get() &&
    {
        return std::forward<T>(this->template Get<T>());
    }

    template <typename T>
    const T&& Get() const&&
    {
        return std::forward<const T>(this->template Get<T>());
    }

    // Explicit R fixes one return type for every branch (including void).
    // Passing a single overloaded function object makes new alternatives a
    // compile-time obligation. Dispatch does not inspect an inactive value.
    template <typename R, typename Visitor>
    R Visit(Visitor&& visitor) &
    {
        static_assert(TypeTraits::All<std::is_same<R, decltype(std::declval<Visitor&>()(VariantDetail::Storage<Alternatives>::Get(std::declval<void*>())))>::value...>::value,
            "Variant visitor must handle every alternative with the declared return type");
        return VariantDetail::VisitDispatch<R, Visitor, void*, 0, Alternatives...>::Apply(mIndex, mStorage, visitor);
    }

    template <typename R, typename Visitor>
    R Visit(Visitor&& visitor) const&
    {
        static_assert(TypeTraits::All<std::is_same<R, decltype(std::declval<Visitor&>()(VariantDetail::Storage<Alternatives>::Get(std::declval<const void*>())))>::value...>::value,
            "Variant visitor must handle every alternative with the declared return type");
        return VariantDetail::VisitDispatch<R, Visitor, const void*, 0, Alternatives...>::Apply(mIndex, mStorage, visitor);
    }

    template <typename T>
    bool Is() const noexcept
    {
        AssertAlternativeType<T>();
        return TypeTraits::Find<T, Alternatives...>::Index == mIndex;
    }

private:
    template <typename T>
    static void AssertAlternativeType() noexcept
    {
        static_assert(1 == TypeTraits::Count<T, Alternatives...>::value, "Variant query requires a listed alternative");
        static_assert(std::is_same<T, typename TypeTraits::Find<T, Alternatives...>::Type>::value,
            "Variant query requires the exact listed cv-qualified type");
    }

    template <typename T>
    void Check() const
    {
        AssertAlternativeType<T>();
        if (TypeTraits::Find<T, Alternatives...>::Index != mIndex)
        {
            throw std::logic_error("Variant: inactive alternative");
        }
    }
};

template <typename... Alternatives>
using Variant = MovableVariant<Alternatives...>;

// Checked typed access; Get validates the listed type and active alternative.
template <typename T, typename... Alternatives>
T& As(MovableVariant<Alternatives...>& variant)
{
    return variant.template Get<T>();
}

template <typename T, typename... Alternatives>
const T& As(const MovableVariant<Alternatives...>& variant)
{
    return variant.template Get<T>();
}

template <typename T, typename... Alternatives>
T&& As(MovableVariant<Alternatives...>&& variant)
{
    return std::move(variant).template Get<T>();
}

template <typename T, typename... Alternatives>
const T&& As(const MovableVariant<Alternatives...>&& variant)
{
    return std::move(variant).template Get<T>();
}
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_VARIANT_HPP
