// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_VARIANT_H
#define COMPLIANCEENGINE_VARIANT_H

#include "TypeTraits.h"

#include <cstddef>
#include <new>
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
            ::new (destination) First(std::move(*static_cast<First*>(source)));
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
            *static_cast<First*>(destination) = std::move(*static_cast<First*>(source));
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
            static_cast<First*>(storage)->~First();
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
        ::new (destination) Last(std::move(*static_cast<Last*>(source)));
    }

    static void MoveAssign(std::size_t, void* destination, void* source) noexcept
    {
        *static_cast<Last*>(destination) = std::move(*static_cast<Last*>(source));
    }

    static void Destroy(std::size_t, void* storage) noexcept
    {
        static_cast<Last*>(storage)->~Last();
    }
};
} // namespace VariantDetail

template <typename... Alternatives>
class MovableVariant
{
    static_assert(0 < sizeof...(Alternatives), "Variant requires at least one alternative");
    static_assert(TypeTraits::Unique<Alternatives...>::value, "Variant alternatives must be distinct, ignoring cv");
    static_assert(TypeTraits::All<!std::is_reference<Alternatives>::value...>::value, "Variant cannot hold references");
    static_assert(TypeTraits::All<!std::is_void<Alternatives>::value...>::value, "Variant cannot hold void");
    static_assert(TypeTraits::All<std::is_nothrow_move_constructible<Alternatives>::value...>::value, "Variant requires nonthrowing move constructors");
    static_assert(TypeTraits::All<std::is_nothrow_move_assignable<Alternatives>::value...>::value, "Variant requires nonthrowing move assignment");
    static_assert(TypeTraits::All<std::is_nothrow_destructible<Alternatives>::value...>::value, "Variant requires nonthrowing destructors");

    alignas(TypeTraits::Max(alignof(Alternatives)...)) char mStorage[TypeTraits::Max(sizeof(Alternatives)...)];
    std::size_t mIndex;

public:
    template <typename T, typename U,
        typename std::enable_if<(1 == TypeTraits::Count<T, Alternatives...>::value) &&
                                    std::is_same<typename std::remove_cv<T>::type, typename std::remove_cv<typename std::remove_reference<U>::type>::type>::value &&
                                    std::is_constructible<typename TypeTraits::Find<T, Alternatives...>::Type, U&&>::value,
            int>::type = 0>
    explicit MovableVariant(InPlaceType<T>, U&& value) noexcept(std::is_nothrow_constructible<typename TypeTraits::Find<T, Alternatives...>::Type, U&&>::value)
        : mIndex(TypeTraits::Find<T, Alternatives...>::Index)
    {
        using Selected = typename TypeTraits::Find<T, Alternatives...>::Type;
        // A failed lvalue copy never completes construction of a Variant.
        ::new (static_cast<void*>(mStorage)) Selected(std::forward<U>(value));
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
        return *reinterpret_cast<T*>(mStorage);
    }

    template <typename T>
    const T& Get() const&
    {
        Check<T>();
        return *reinterpret_cast<const T*>(mStorage);
    }

    template <typename T>
    T&& Get() &&
    {
        return std::move(this->template Get<T>());
    }

    template <typename T>
    const T&& Get() const&&
    {
        return std::move(this->template Get<T>());
    }

private:
    template <typename T>
    void Check() const
    {
        static_assert(1 == TypeTraits::Count<T, Alternatives...>::value, "Get<T> requires a listed alternative");
        static_assert(std::is_same<T, typename TypeTraits::Find<T, Alternatives...>::Type>::value,
            "Get<T> requires the exact listed cv-qualified type");
        if (TypeTraits::Find<T, Alternatives...>::Index != mIndex)
        {
            throw std::logic_error("Variant: inactive alternative");
        }
    }
};

template <typename... Alternatives>
using Variant = MovableVariant<Alternatives...>;
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_VARIANT_H
